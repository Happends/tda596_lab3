package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	ctfp "chord/chordFileTransfer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TODO: fixa fingertable
// TODO: fixa successor listan
// TODO: fixa filer
// TODO: fixa mutex

// TODO: encryption
// TODO: säerhetskopiera filer
// TODO: secure file transfer

//	type NodeIdentifier struct {
//		Id      string
//		Address string
//	}
type Key string
type NodeAddress string

type ChordNode struct {
	Id          Key
	Address     NodeAddress
	Fingers     []NodeAddress
	Predecessor NodeAddress
	Successors  []NodeAddress

	Bucket map[string][]byte

	ExtraBucket map[string][]byte

	n_successors int
	ts           int
	tff          int
	tcp          int
	mutex        sync.Mutex

	AESkey        []byte
	RSAkeyPrivate []byte
	RSAkeyPublic  []byte
	ServerConfig  tls.Config
	ClientConfig  tls.Config
	CaCertPool    *x509.CertPool

	ctfp.UnimplementedChordFileTransferServer
}

//	func (n *ChordNode) background() {
//		for i := 0; i < 15; i++ {
//			n.fix_fingers()
//			time.Sleep(333 * time.Millisecond)
//			// n.check_predecessor()
//			time.Sleep(333 * time.Millisecond)
//		}
//		n.PrintState(&Empty{}, &Empty_reply{})
//	}

func (n *ChordNode) background_stabilize() {
	for {
		n.stabilize()
		time.Sleep(time.Duration(n.ts) * time.Millisecond)
	}
}

func (n *ChordNode) background_fix_fingers() {
	for {
		n.fix_fingers()
		time.Sleep(time.Duration(n.tff) * time.Millisecond)
	}
}

func (n *ChordNode) background_check_predecessor() {
	for {
		n.check_predecessor()
		time.Sleep(time.Duration(n.tcp) * time.Millisecond)
	}
}

func main() {

	ip := ""
	port := -1
	chord_ip := ""
	chord_port := -1
	ts := 500
	tff := 500
	tcp := 500
	n_successors := 5
	id := ""
	background := 0

	for i := 1; i < len(os.Args); i += 2 {
		fmt.Println("arg: ", os.Args[i], ", parameter: ", os.Args[i+1])
		var err error = nil
		switch os.Args[i] {
		case "-a":
			if os.Args[i+1] != "-1" {
				ip = os.Args[i+1]
			}
		case "-p":
			port, err = strconv.Atoi(os.Args[i+1])
			if port < 0 || port > 65535 {
				fmt.Println("invalid port argument: ", port)
				return
			}
		case "--ja":
			if os.Args[i+1] != "-1" {
				chord_ip = os.Args[i+1]
			}
		case "--jp":
			chord_port, err = strconv.Atoi(os.Args[i+1])
			if (chord_port < 0 || chord_port > 65535) && chord_port != -1 {
				fmt.Println("invalid chord_port argument: ", chord_port)
				return
			}
		case "--ts":
			ts, err = strconv.Atoi(os.Args[i+1])
			if ts < 1 || ts > 60000 {
				fmt.Println("invalid ts argument: ", ts)
				return
			}
		case "--tff":
			tff, err = strconv.Atoi(os.Args[i+1])
			if tff < 1 || tff > 60000 {
				fmt.Println("invalid tff argument: ", tff)
				return
			}
		case "--tcp":
			tcp, err = strconv.Atoi(os.Args[i+1])
			if tcp < 1 || tcp > 60000 {
				fmt.Println("invalid tcp argument: ", tcp)
				return
			}
		case "-r":
			n_successors, err = strconv.Atoi(os.Args[i+1])
			if n_successors < 1 || n_successors > 32 {
				fmt.Println("invalid r argument: ", n_successors)
				return
			}
		case "-i":
			id = os.Args[i+1]
			notValid := false
			for _, l := range id {
				if !((l >= 'a' && l <= 'f') || (l >= 'A' && l <= 'F') || unicode.IsDigit(l)) {
					notValid = true
				}
			}
			if notValid || len(id) != 40 {
				fmt.Println("id should be 40 characters of [0-9a-fA-F]: ", id)
				return
			}
		case "-d":
			background, err = strconv.Atoi(os.Args[i+1])
			if err != nil {
				background = 0
			}
		}

		if err != nil {
			fmt.Println("exception when formating argument: ", os.Args[i], " value is:", os.Args[i+1])
			return

		}

	}

	if ip == "" || port == -1 {
		fmt.Println("-a and -p must be specified: ", ip, ":", port)
		return
	}

	if (chord_port != -1 && chord_ip == "") || (chord_port == -1 && chord_ip != "") {
		fmt.Println("if either jp or ja is specified the other must be specified: ", chord_ip, ":", chord_port)
	}

	// create chord
	port_string := strconv.Itoa(port)
	node := CreateChord(ip, port_string, n_successors, ts, tff, tcp, id)

	// create rsa keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("unable to generate rsa key")
		return
	}
	node.RSAkeyPrivate = x509.MarshalPKCS1PrivateKey(privateKey)
	node.RSAkeyPublic = x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	// template := x509.Certificate{
	// 	SerialNumber: big.NewInt(1),
	// 	Issuer: pkix.Name{
	// 		Organization: []string{"Bros Org"},
	// 		CommonName:   "localhost",
	// 	},
	// 	Subject: pkix.Name{
	// 		Organization: []string{"Bros Org"},
	// 		CommonName:   "localhost",
	// 	},
	// 	NotBefore:   time.Now(),
	// 	NotAfter:    time.Now().AddDate(0, 0, 1), // one day
	// 	IsCA:        false,
	// 	KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	// 	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	// 	DNSNames:    []string{"localhost"},
	// 	IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	// }
	// caCert, err := os.ReadFile("ca.crt")
	// if err != nil {
	// 	fmt.Println("Error reading CA certificate:", err)
	// 	return
	// }
	// caBlock, _ := pem.Decode(caCert)
	// caCertParsed, err := x509.ParseCertificate(caBlock.Bytes)
	// node.CaCert = caCertParsed
	// if err != nil {
	// 	fmt.Println("Error parsing CA certificate:", err)
	// 	return
	// }

	// caKey, err := os.ReadFile("ca.key")
	// if err != nil {
	// 	fmt.Println("Error reading CA private key:", err)
	// 	return
	// }
	// caKeyBlock, _ := pem.Decode(caKey)
	// caPrivateKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	// if err != nil {
	// 	fmt.Println("Error parsing CA private key:", err)
	// 	return
	// }

	// certificate, err := x509.CreateCertificate(rand.Reader, &template, caCertParsed, &privateKey.PublicKey, caPrivateKey)
	// if err != nil {
	// 	fmt.Println("could not initiate certificate: ", err)
	// 	return
	// }
	// node.ServerCert = certificate
	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatal("Failed to read CA certificate:", err)
	}

	// Parse the PEM-encoded certificate
	block, _ := pem.Decode(caCert)
	if block == nil {
		log.Fatalf("Failed to parse PEM block containing the certificate")
	}

	// // Load the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	fmt.Println("cert ips:")
	fmt.Println(cert.IPAddresses)

	// Create a certificate pool
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	node.CaCertPool = certPool

	serverCert, err := tls.LoadX509KeyPair("server_signed.crt", "server.key")
	if err != nil {
		log.Fatalf("Failed to load server certificate and key: %v", err)
	}
	node.ServerConfig = tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs: certPool,
	}

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair("client_signed.crt", "client.key")
	if err != nil {
		log.Fatalf("Failed to load client certificate and key: %v", err)
	}

	// Create TLS credentials for the client
	node.ClientConfig = tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	// fmt.Println("cert:")
	// fmt.Println(cert)
	// fmt.Println("dnsNames:")
	// fmt.Println(cert.DNSNames)
	// fmt.Println("email:")
	// fmt.Println(cert.EmailAddresses)
	// fmt.Println("IP:")
	// fmt.Println(cert.IPAddresses)
	// fmt.Println("uris:")
	// fmt.Println(cert.URIs)
	// return

	node.startChord()

	// join chord if specified
	if chord_ip != "" && chord_port != -1 {
		fmt.Println("joining!")
		port_string := strconv.Itoa(chord_port)
		err := node.join(NodeAddress(chord_ip + ":" + port_string))
		if err != nil {
			fmt.Println("unable to join chord ring: ", err)
			return
		}
		fmt.Println("succesful join!")
	} else {

		key, r := generateRandomKey(32)
		if r != nil {
			fmt.Println("Error generating key: ", r)
			return
		}
		node.AESkey = key
	}

	// testing printState
	arg := ctfp.EmptyArgs{}
	reply := ctfp.EmptyReply{}
	node.call(string(node.Address), "PrintState", &arg, &reply)
	// time.Sleep(10 * time.Second)

	if background == 0 {
		for {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			text = strings.Trim(text, "\n \t\r")
			textArr := strings.Fields(text)
			fmt.Println(textArr)
			if len(textArr) == 0 {
				fmt.Println("invalid command: ", text)
				continue
			}
			fmt.Println(textArr[0])
			switch textArr[0] {
			case "Lookup":
				if len(textArr) < 2 {
					fmt.Println("invalid argument: ", text)
					continue
				}
				node.Lookup(textArr[1])
			case "StoreFile":
				if len(textArr) < 2 {
					fmt.Println("invalid argument: ", text)
					continue
				}
				node.StoreFile(textArr[1])
			case "PrintState":
				node.PrintState(context.TODO(), &ctfp.EmptyArgs{})
			default:
				fmt.Println("invalid command: ", text)
			}
		}
	}
	for {
	}

}

func (node *ChordNode) closest_preceding_node(id Key) (bool, NodeAddress) {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	for i := len(id) - 1; i >= 0; i-- {
		if between(node.Id, bigInt_to_key(hashAddress(node.Fingers[i])), id, false) {
			return true, node.Fingers[i]
		}
	}
	return false, node.Address
}

func (n *ChordNode) FindSuccessor(ctx context.Context, args *ctfp.FindSuccessorArgs) (*ctfp.FindSuccessorReply, error) {
	reply := ctfp.FindSuccessorReply{}
	// if node.Fingers[0] == node.Address {
	// 	reply.Address = node.Address
	// 	reply.Ok = false
	// 	return nil
	// }
	id := Key(args.Key)
	// fmt.Println("arg: ", arg.Id)
	// fmt.Println("before getting successor")
	succ := n.get_successor()
	// fmt.Println("gotten successor")
	if between(n.Id, id, bigInt_to_key(hashAddress(succ)), true) {
		reply.Address = string(succ)
		reply.Ok = true
		return &reply, nil
	} else {
		ok, nodeAddress := n.closest_preceding_node(id)
		if ok {
			newArgs := ctfp.FindSuccessorArgs{Key: args.Key}
			callOk := n.call(string(nodeAddress), "FindSuccessor", &newArgs, &reply)
			if callOk {
				return &reply, nil
			} else {
				return nil, errors.New("call to node on FindSuccessor did not go through")
			}
		} else {
			reply.Address = string(nodeAddress)
			reply.Ok = false
			fmt.Println("couldn't find closest preceding node id: ", id)
			fmt.Println("at node: ", nodeAddress)
			fmt.Println("update fingers unable, waiting til next iteration")
			return &reply, nil
		}
	}

}

func (newNode *ChordNode) join(address NodeAddress) error {
	newNode.mutex.Lock()
	newNode.Predecessor = ""
	newNode.mutex.Unlock()
	args := ctfp.FindSuccessorArgs{Key: string(newNode.Id)}
	reply := ctfp.FindSuccessorReply{}
	ok := newNode.call(string(address), "FindSuccessor", &args, &reply)
	if !ok {
		fmt.Println("could not join address, call issue: ", string(address))
		return errors.New("could not join address, call issue")
	} else if !reply.Ok {
		fmt.Println("could not join address, FindSuccessor issue: ", string(address))
		return errors.New("could not join address, FindSuccessor issue")
	}

	keyArgs := ctfp.GetAESKeyArgs{Key: newNode.RSAkeyPublic}
	keyReply := ctfp.GetAESKeyReply{}

	ok = newNode.call(string(reply.Address), "GetAESKey", &keyArgs, &keyReply)
	if !ok {
		fmt.Println("could not join address, call issue: ", string(address))
		return errors.New("could not join address, call issue")
	}

	rsakey, _ := x509.ParsePKCS1PrivateKey(newNode.RSAkeyPrivate)
	AESKey, err := RSA_OAEP_Decrypt(keyReply.AESKey, *rsakey)
	if err != nil {
		fmt.Println("unable to decrypt aes key")
		return errors.New("cunable to decrypt aes key")
	}
	newNode.AESkey = AESKey
	newNode.add_successor(NodeAddress(reply.Address))
	fmt.Println("successors changed: ", newNode.get_successor())
	return nil
}

func (n *ChordNode) fix_fingers() {
	for i := range n.Fingers {
		// fmt.Println(jump(node.Address, i))
		arg := ctfp.FindSuccessorArgs{Key: string(jump(n.Address, i))}
		reply, err := n.FindSuccessor(context.Background(), &arg)
		if err != nil {
			fmt.Println("FindSuccessor error: ", err)
			return
		}
		if reply.Ok {

			n.mutex.Lock()
			n.Fingers[i] = NodeAddress(reply.Address)
			n.mutex.Unlock()
		} else {
			fmt.Println("FindSuccessor error in fix_fingers: ")
		}
	}
}

func (node *ChordNode) stabilize() {
	if len(node.Successors) <= 0 {
		return
	}
	reply := ctfp.GetPredecessorReply{}
	// fmt.Println("asking: ", string(node.Successors[0]), " for predecessor: ", reply.Address)
	for {
		if node.call(string(node.get_successor()), "GetPredecessor", &ctfp.GetPredecessorArgs{}, &reply) {
			break
		}
		fmt.Println("could not call predecessor: ", node.get_successor())
		if !node.remove_successor() {
			fmt.Println("error? only one chord left?")
		}
	}

	reply_id := bigInt_to_key(hashAddress(NodeAddress(reply.Address)))
	transfer_files := false
	if reply.Address != "" && between(node.Id, reply_id, bigInt_to_key(hashAddress(node.get_successor())), false) {
		node.add_successor(NodeAddress(reply.Address))
		transfer_files = true
	}

	kvpairs := []*ctfp.KeyValuePair{}
	for k, v := range node.Bucket {
		kvpairs = append(kvpairs, &ctfp.KeyValuePair{Key: k, Value: v})
	}
	arg := ctfp.NotifyArgs{Address: string(node.Address), Bucket: kvpairs}
	notifyReply := ctfp.NotifyReply{}
	notifyCallOk := node.call(string(node.get_successor()), "Notify", &arg, &notifyReply)
	if !notifyCallOk {
		fmt.Println("call to successor to notify err: ", node.get_successor())
		return
	} //else if !notifyReply.Confirm {
	// fmt.Println("Successor did not update it's predecessor after notify: ", node.get_successor())
	//	return
	//}
	// if len(node.AESkey) == 0 && len(notifyReply.Key) > 0 {
	// 	node.key = notifyReply.Key
	// }
	pre_id := bigInt_to_key(hashAddress(node.Predecessor))
	// fmt.Println("bucket: ", notifyReply.Bucket)
	for _, kv := range notifyReply.Bucket {
		if between(pre_id, bigInt_to_key(hashFileName(kv.Key)), node.Id, true) {
			node.Bucket[kv.Key] = kv.Value
		}
	}

	if transfer_files {
		successor_id := bigInt_to_key(hashAddress(node.get_successor()))
		for file := range node.Bucket {
			if between(node.Id, bigInt_to_key(hashFileName(file)), successor_id, true) {
				delete(node.Bucket, file)
			}
		}
	}

	successorsArg := ctfp.GetSuccessorsArgs{}
	successorsReply := ctfp.GetSuccessorsReply{}
	successorsCallOk := node.call(string(node.get_successor()), "GetSuccessors", &successorsArg, &successorsReply)
	if !successorsCallOk {
		fmt.Println("call to successor to get successors err: ", node.get_successor())
		return
	}
	successors := []NodeAddress{}
	for i := 0; i < len(successorsReply.Successors); i++ {
		successors = append(successors, NodeAddress(successorsReply.Successors[i]))
	}
	node.mutex.Lock()
	copy(node.Successors[1:], successors[:len(successors)-1])
	node.mutex.Unlock()
}

func (node *ChordNode) GetPredecessor(ctx context.Context, arg *ctfp.GetPredecessorArgs) (*ctfp.GetPredecessorReply, error) {
	reply := ctfp.GetPredecessorReply{}
	node.mutex.Lock()
	defer node.mutex.Unlock()
	reply.Address = string(node.Predecessor)
	// fmt.Println("sending predecessor: ", reply.Address)
	return &reply, nil
}

func (node *ChordNode) GetSuccessors(ctx context.Context, arg *ctfp.GetSuccessorsArgs) (*ctfp.GetSuccessorsReply, error) {
	reply := ctfp.GetSuccessorsReply{}
	node.mutex.Lock()
	defer node.mutex.Unlock()
	reply.Successors = []string{}
	for _, successor := range node.Successors {
		reply.Successors = append(reply.Successors, string(successor))
	}
	return &reply, nil
}

func (node *ChordNode) check_predecessor() {
	if node.Predecessor == "" {
		return
	}
	arg := ctfp.GetPredecessorArgs{}
	reply := ctfp.GetPredecessorReply{}
	callOk := node.call(string(node.Predecessor), "GetPredecessor", &arg, &reply)
	if !callOk {
		fmt.Println("predecessor call failed: ", node.Predecessor)
		node.mutex.Lock()
		for file, content := range node.ExtraBucket {
			node.Bucket[file] = content
		}
		node.ExtraBucket = map[string][]byte{}
		node.Predecessor = ""
		node.mutex.Unlock()
	}
}

func (node *ChordNode) Notify(ctx context.Context, arg *ctfp.NotifyArgs) (*ctfp.NotifyReply, error) {
	reply := ctfp.NotifyReply{}
	id := bigInt_to_key(hashAddress(NodeAddress(arg.Address)))
	// fmt.Println("node.Predecessor: ", node.Predecessor)
	if node.Predecessor == "" || between(bigInt_to_key(hashAddress(node.Predecessor)), id, node.Id, false) {
		reply.Bucket = []*ctfp.KeyValuePair{}
		node.mutex.Lock()
		node.Predecessor = NodeAddress(arg.Address)
		pre_id := bigInt_to_key(hashAddress(NodeAddress(arg.Address)))
		for file, content := range node.Bucket {
			reply.Bucket = append(reply.Bucket, &ctfp.KeyValuePair{Key: file, Value: content})
			if !between(pre_id, bigInt_to_key(hashFileName(file)), node.Id, true) {
				delete(node.Bucket, file)
			}
		}
		// if len(node.key) > 0 {
		// 	reply.Key = node.key
		// }
		node.mutex.Unlock()
		reply.Confirm = true
		if node.Address == node.get_successor() {
			node.mutex.Lock()
			node.Successors[0] = NodeAddress(arg.Address)
			node.mutex.Unlock()
		}
	} else {
		reply.Confirm = false
	}
	if node.Predecessor == NodeAddress(arg.Address) {
		node.mutex.Lock()
		pre_id := bigInt_to_key(hashAddress(node.Predecessor))
		node.ExtraBucket = map[string][]byte{}
		for _, kv := range arg.Bucket {
			if between(pre_id, bigInt_to_key(hashFileName(kv.Key)), node.Id, true) {
				node.Bucket[kv.Key] = kv.Value
			} else {
				node.ExtraBucket[kv.Key] = kv.Value
			}
		}
		node.mutex.Unlock()
	}
	return &reply, nil
}

func (n *ChordNode) Put(ctx context.Context, args *ctfp.PutArgs) (*ctfp.PutReply, error) {
	reply := ctfp.PutReply{}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	fmt.Println("put file: ", args.FileName)

	n.Bucket[args.FileName] = args.FileContent // security issue?
	reply.Confirm = true
	return &reply, nil
}

func (n *ChordNode) Get(ctx context.Context, args *ctfp.GetArgs) (*ctfp.GetReply, error) {
	reply := ctfp.GetReply{}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	reply.Confirm = false
	val, ok := n.Bucket[args.FileName]
	// fmt.Println("get: ", args.FileName, " content: ", string(val))
	if ok {
		reply.Confirm = true
		reply.Content = val
	}

	return &reply, nil // security issue?
}

func (n *ChordNode) Delete(ctx context.Context, args *ctfp.DeleteArgs) (*ctfp.DeleteReply, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	reply := ctfp.DeleteReply{}
	fmt.Println("delete: ", args.FileName)
	reply.Confirm = false
	_, ok := n.Bucket[args.FileName]
	if !ok {
		delete(n.Bucket, args.FileName)
		reply.Confirm = true
	}

	return &reply, nil
}

func (n *ChordNode) StoreFile(fileName string) {
	file, err := os.Open(fileName)

	if err != nil {
		fmt.Println("file can't be opened: ", file, " err: ", err)
		return
	}
	defer file.Close()

	bytes, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Println("could not read file: ", fileName)
		return
	}

	bytes, r := aesEncyption(bytes, n.AESkey)
	if r != nil {
		fmt.Println("ErrorEncyptio:", r)
	}
	// fmt.Println("this is the encrypted data:", bytes)

	arg := ctfp.FindSuccessorArgs{Key: string(bigInt_to_key(hashFileName(fileName)))}
	reply, err := n.FindSuccessor(context.Background(), &arg)
	if err != nil {
		fmt.Println("FindSuccessor error: ", err)
		return
	}
	if !reply.Ok {
		fmt.Println("could not find closest, try again!")
		return
	}
	putArgs := ctfp.PutArgs{FileName: fileName, FileContent: bytes}
	putReply := ctfp.PutReply{}
	callOk := n.call(string(reply.Address), "Put", &putArgs, &putReply)

	if !callOk {
		fmt.Println("call to put file on node failed: ", reply.Address)
		return
	}
	if !putReply.Confirm {
		fmt.Println("could not store file: ", fileName)
		return
	}
}

func (n *ChordNode) Lookup(fileName string) {
	arg := ctfp.FindSuccessorArgs{Key: string(bigInt_to_key(hashFileName(fileName)))}
	reply, err := n.FindSuccessor(context.Background(), &arg)
	if err != nil {
		fmt.Println("FindSuccessor error: ", err)
		return
	}

	if !reply.Ok {
		fmt.Println("could not find closest, try again!")
		return
	}
	getArgs := ctfp.GetArgs{FileName: fileName}
	getReply := ctfp.GetReply{}
	callOk := n.call(string(reply.Address), "Get", &getArgs, &getReply)

	if !callOk {
		fmt.Println("call to get file on node failed: ", reply.Address)
		return
	}
	if !getReply.Confirm {
		fmt.Println("could not get file: ", fileName)
		return
	}

	orginalData, r := aesdecrption(getReply.Content, n.AESkey)
	if r != nil {
		fmt.Println("Error decrypted data:", r)
		return
	}
	// fmt.Println("this is the decrypted data:", orginalData)

	fmt.Println("Identifier: ", bigInt_to_key(hashAddress(NodeAddress(reply.Address))), " Address: ", string(reply.Address), " Content: \n", string(orginalData))
}

func (n *ChordNode) PrintState(ctx context.Context, message *ctfp.EmptyArgs) (*ctfp.EmptyReply, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	fmt.Println("\n\nNode:")
	fmt.Println("Predecessor: ", n.Predecessor)
	fmt.Println("Id: ", n.Id)
	fmt.Println("Address: ", n.Address)
	fmt.Println("n_successors: ", n.n_successors)
	fmt.Println("ts: ", n.ts)
	fmt.Println("tff: ", n.tff)
	fmt.Println("tcp: ", n.tcp)
	fmt.Println("Successors: ")
	for i, successor := range n.Successors {
		fmt.Println("	", i, ": ", successor, " id: ", bigInt_to_key(hashAddress(successor)))
	}
	fmt.Println("Fingers: ")
	for i, finger := range n.Fingers {
		fmt.Println("	", i, ": ", finger, " id: ", bigInt_to_key(hashAddress(finger)))
	}
	fmt.Println("Files: ")
	for file := range n.Bucket {
		fmt.Println("	", file)
	}
	fmt.Println("Safety Files: ")
	for file := range n.ExtraBucket {
		fmt.Println("	", file)
	}

	return &ctfp.EmptyReply{}, nil
}

// func (n *ChordNode) closest_preceding_node(id) {
// 	fmt.Println("closest_preceding_node: ", id)

func CreateChord(ip string, port string, n_successors int, ts int, tff int, tcp int, id string) *ChordNode {

	address := ip + ":" + port
	// id := hashString(ip + ":" + port)
	node := ChordNode{ts: ts, tff: tff, tcp: tcp, Address: NodeAddress(address), Id: Key(id)}

	node.Fingers = make([]NodeAddress, 40*4)
	for i := range node.Fingers {
		node.Fingers[i] = node.Address
	}
	node.Bucket = map[string][]byte{}
	node.Predecessor = ""
	node.n_successors = n_successors
	node.Successors = make([]NodeAddress, n_successors)
	for i := range node.Successors {
		node.Successors[i] = node.Address
	}
	node.Id = bigInt_to_key(hashAddress(node.Address))

	return &node
}

func (node *ChordNode) startChord() {

	node.grpc_server()

	go node.background_stabilize()

	go node.background_fix_fingers()

	go node.background_check_predecessor()
}

// func (node *ChordNode) server() error {
// 	rpc.Register(node)
// 	rpc.HandleHTTP()

// 	l, e := net.Listen("tcp", string(node.Address))
// 	if e != nil {
// 		fmt.Println("unable to start node rpc server: ", e)
// 		return e
// 	}

// 	go http.Serve(l, nil)

// 	return nil
// }

func (node *ChordNode) grpc_server() error {
	l, e := net.Listen("tcp", string(node.Address))
	if e != nil {
		fmt.Println("unable to start node rpc server: ", e)
		return e
	}

	grpc_server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&node.ServerConfig)))

	ctfp.RegisterChordFileTransferServer(grpc_server, node)

	go grpc_server.Serve(l)

	return nil
}

func (node *ChordNode) call(address string, rpcname string, args interface{}, reply interface{}) bool {
	// fmt.Println("address: ", address)
	// fmt.Println("rpcname: ", rpcname)
	// certificates, err := x509.ParseCertificates()
	// if err != nil {
	// 	fmt.Println("could not parse certificate in call...?")
	// 	return false
	// }

	c, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&node.ClientConfig)))
	if err != nil {
		fmt.Println("dialing error:", err)
		return false
	}
	defer c.Close()

	method := "ChordFileTransfer/" + rpcname
	err = c.Invoke(context.Background(), method, args, reply)
	if err == nil {
		return true
	}

	fmt.Println("calling error: ", err)
	return false
}

// func (n *ChordNode) JoinChord(Address string) {
//	for {

//		req := SuccFind{Id: n.nId.Id}
//		rep := Bingo{}
//		call(Address, &req, &rep)
//		n.Successor[0] = rep.SuccId
//		if rep.Identified {
//			break
//		}
//
//	}

//}

// func between(start *big.Int, id *big.Int, end *big.Int, inclusive bool) bool {
// 	if end.Cmp(start) > 0 {
// 		return (start.Cmp(id) < 0 && id.Cmp(end) < 0) || (inclusive && id.Cmp(end) == 0)
// 	} else {
// 		return start.Cmp(id) < 0 || id.Cmp(end) < 0 || (inclusive && id.Cmp(end) == 0)
// 	}
// }

// helpers
func between(start Key, id Key, end Key, inclusive bool) bool {
	if end > start {
		return (start < id && id < end) || (inclusive && id == end)
	} else {
		return start < id || id < end || (inclusive && id == end)
	}
}

func bigInt_to_key(big_int *big.Int) Key {
	return Key(fmt.Sprintf("%x", big_int))
}

// func key_to_bigInt(id Key) (*big.Int, bool) {
// 	value, ok := new(big.Int).SetString(string(id), 16)
// 	return value, ok
// }

func jump(address NodeAddress, fingerentry int) Key {
	var keySize = int64(crypto.SHA1.Size() * 8)
	var hashMod = new(big.Int).Exp(big.NewInt(2), big.NewInt(keySize), nil)
	addressHash := hashAddress(address)
	entry := big.NewInt(int64(fingerentry))
	jump := new(big.Int).Exp(big.NewInt(2), entry, nil)
	sum := new(big.Int).Add(addressHash, jump)

	return bigInt_to_key(new(big.Int).Mod(sum, hashMod))
}

func hashAddress(address NodeAddress) *big.Int {
	hasher := crypto.SHA1.New()
	hasher.Write([]byte(string(address)))
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

func hashFileName(fileName string) *big.Int {
	hasher := crypto.SHA1.New()
	hasher.Write([]byte(string(fileName)))
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

// successors helpers

func (node *ChordNode) add_successor(successor NodeAddress) {

	node.mutex.Lock()
	defer node.mutex.Unlock()
	if node.Successors[0] == successor {
		fmt.Println("successor cannot be added since successor already first: ", successor)
		return
	}
	for i := len(node.Successors) - 1; i >= 1; i-- {
		node.Successors[i] = node.Successors[i-1]
	}
	node.Successors[0] = successor
}

func (node *ChordNode) remove_successor() bool {

	node.mutex.Lock()
	defer node.mutex.Unlock()
	if node.Successors[0] == node.Address {
		fmt.Println("successor cannot be remove since node is first successor: ", node.Successors[0])
		return false
	}
	for i := len(node.Successors) - 1; i >= 1; i-- {
		node.Successors[i-1] = node.Successors[i]
	}
	node.Successors[len(node.Successors)-1] = node.Address
	return false
}

func (node *ChordNode) get_successor() NodeAddress {
	node.mutex.Lock()
	defer node.mutex.Unlock()

	return node.Successors[0]
}

// -------------------------------encryption------------------------------------------------

func padding(data []byte, blockSize int) []byte {
	valueToPad := blockSize - len(data)%blockSize
	padText := make([]byte, valueToPad)
	for i := 0; i < len(padText); i++ {
		padText[i] = byte(valueToPad)
	}
	return append(data, padText...)
}

func generateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, r := io.ReadFull(rand.Reader, key)
	if r != nil {
		fmt.Println("Error generating new key:", r)
	}
	return key, nil
}

func aesEncyption(data []byte, key []byte) ([]byte, error) {
	block, r := aes.NewCipher(key)
	if r != nil {
		fmt.Println("Error generating new cipher:", r)
	}

	// generating a random iv
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		fmt.Println("Error generating iv:", err)
	}

	//makineg the text a multiple of the block size
	paddeddata := padding(data, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv) // create a CBC mode encrypter
	cipherData := make([]byte, len(paddeddata))
	mode.CryptBlocks(cipherData, paddeddata) //encrypting data
	finalCipherData := append(iv, cipherData...)

	return finalCipherData, nil

}

func aesdecrption(finalCipherData []byte, key []byte) ([]byte, error) {
	block, r := aes.NewCipher(key)
	if r != nil {
		fmt.Println("Error generating new cipher:", r)
	}

	iv := finalCipherData[:aes.BlockSize]
	finalCipherData = finalCipherData[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	data := make([]byte, len(finalCipherData))
	mode.CryptBlocks(data, finalCipherData)
	data = unpadding(data)
	return data, nil

}

func unpadding(data []byte) []byte {
	length := len(data)
	padding := int(data[length-1])
	return data[:length-padding]
}

// RSA encryption
func RSA_OAEP_Encrypt(data []byte, key rsa.PublicKey) ([]byte, error) {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	encoded, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(data), label)
	if err != nil {
		fmt.Println("unable to encrypt message")
		return nil, err
	}
	return encoded, nil
}

func RSA_OAEP_Decrypt(encoded []byte, privKey rsa.PrivateKey) ([]byte, error) {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	data, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, encoded, label)
	if err != nil {
		fmt.Println("unable to decrypt message")
		return nil, err
	}
	return data, nil
}

func (node *ChordNode) GetAESKey(ctx context.Context, args *ctfp.GetAESKeyArgs) (*ctfp.GetAESKeyReply, error) {
	reply := ctfp.GetAESKeyReply{}
	rsaKey, _ := x509.ParsePKCS1PublicKey(args.Key)
	encodedAES, err := RSA_OAEP_Encrypt(node.AESkey, *rsaKey)
	if err != nil {
		fmt.Println("unable to encrypt aes: ", err)
		return nil, errors.New("unable to encrypt aes")
	}
	reply.AESKey = encodedAES
	return &reply, nil
}
