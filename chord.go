package main

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
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

	key []byte
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

	for i := 1; i < len(os.Args); i += 2 {
		fmt.Println("arg: ", os.Args[i], ", parameter: ", os.Args[i+1])
		var err error = nil
		switch os.Args[i] {
		case "-a":
			ip = os.Args[i+1]
		case "-p":
			port, err = strconv.Atoi(os.Args[i+1])
			if port < 0 || port > 65535 {
				fmt.Println("invalid port argument: ", port)
				return
			}
		case "--ja":
			chord_ip = os.Args[i+1]
		case "--jp":
			chord_port, err = strconv.Atoi(os.Args[i+1])
			if chord_port < 0 || chord_port > 65535 {
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

	// join chord if specified
	if chord_ip != "" && chord_port != -1 {
		fmt.Println("joining!")
		port_string := strconv.Itoa(chord_port)
		node.join(NodeAddress(chord_ip + ":" + port_string))
	} else {

		key, r := generateRandomKey(32)
		if r != nil {
			fmt.Println("Error generating key:", r)
			return
		}
		node.key = key
	}

	// testing printState
	arg := Empty{}
	reply := EmptyReply{}
	call(string(node.Address), "ChordNode.PrintState", &arg, &reply)
	// time.Sleep(10 * time.Second)

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
			node.PrintState(&Empty{}, &EmptyReply{})
		default:
			fmt.Println("invalid command: ", text)
		}
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

func (node *ChordNode) Find_successor(arg *FindClosestSuccessor, reply *FindClosestSuccessorReply) error {
	// if node.Fingers[0] == node.Address {
	// 	reply.Address = node.Address
	// 	reply.Ok = false
	// 	return nil
	// }
	id := arg.Id
	// fmt.Println("arg: ", arg.Id)
	// fmt.Println("before getting successor")
	succ := node.get_successor()
	// fmt.Println("gotten successor")
	if between(node.Id, id, bigInt_to_key(hashAddress(succ)), true) {
		reply.Address = succ
		reply.Ok = true
		return nil
	} else {
		ok, nodeAddress := node.closest_preceding_node(id)
		if ok {
			callOk := call(string(nodeAddress), "ChordNode.Find_successor", &arg, &reply)
			if callOk {
				return nil
			} else {
				return errors.New("call to node on find_successor did not go through")
			}
		} else {
			reply.Address = nodeAddress
			reply.Ok = false
			fmt.Println("couldn't find closest preceding node id: ", id)
			fmt.Println("at node: ", nodeAddress)
			fmt.Println("needs more time to update fingers")
			return nil
		}
	}

}

func (newNode *ChordNode) join(address NodeAddress) {
	newNode.mutex.Lock()
	newNode.Predecessor = ""
	newNode.mutex.Unlock()
	args := FindClosestSuccessor{Id: newNode.Id}
	reply := FindClosestSuccessorReply{}
	fmt.Println("pre-call")
	ok := call(string(address), "ChordNode.Find_successor", &args, &reply)
	fmt.Println("post-call")
	if !ok {
		fmt.Println("could not join address, call issue: ", string(address))
		return
	} else if !reply.Ok {
		fmt.Println("could not join address, find_successor issue: ", string(address))
		return
	}
	newNode.add_successor(reply.Address)
	fmt.Println("successors changed: ", newNode.get_successor())

}

func (node *ChordNode) fix_fingers() {
	for i := range node.Fingers {
		// fmt.Println(jump(node.Address, i))
		arg := FindClosestSuccessor{Id: jump(node.Address, i)}
		reply := FindClosestSuccessorReply{}
		node.Find_successor(&arg, &reply)
		if reply.Ok {

			node.mutex.Lock()
			node.Fingers[i] = reply.Address
			node.mutex.Unlock()
		} else {
			fmt.Println("find_successor error in fix_fingers: ")
		}
	}
}

func (node *ChordNode) stabilize() {
	if len(node.Successors) <= 0 {
		return
	}
	reply := GetPredecessorReply{}
	// fmt.Println("asking: ", string(node.Successors[0]), " for predecessor: ", reply.Address)
	for {
		if call(string(node.get_successor()), "ChordNode.GetPredecessor", &GetPredecessor{}, &reply) {
			break
		}
		fmt.Println("could not call predecessor: ", node.get_successor())
		if !node.remove_successor() {
			fmt.Println("error? only one chord left?")
		}
	}

	reply_id := bigInt_to_key(hashAddress(reply.Address))
	transfer_files := false
	if reply.Address != "" && between(node.Id, reply_id, bigInt_to_key(hashAddress(node.get_successor())), false) {
		node.add_successor(reply.Address)
		transfer_files = true
	}

	arg := Notify{Address: node.Address, Bucket: node.Bucket}
	notifyReply := NotifyReply{}
	notifyCallOk := call(string(node.get_successor()), "ChordNode.Notify", &arg, &notifyReply)
	if !notifyCallOk {
		fmt.Println("call to successor to notify err: ", node.get_successor())
		return
	} //else if !notifyReply.Confirm {
	// fmt.Println("Successor did not update it's predecessor after notify: ", node.get_successor())
	//	return
	//}
	if len(node.key) == 0 && len(notifyReply.Key) > 0 {
		node.key = notifyReply.Key
	}
	pre_id := bigInt_to_key(hashAddress(node.Predecessor))
	// fmt.Println("bucket: ", notifyReply.Bucket)
	for file, content := range notifyReply.Bucket {
		if between(pre_id, bigInt_to_key(hashFileName(file)), node.Id, true) {
			node.Bucket[file] = content
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

	successorsArg := GetSuccessors{}
	successorsReply := GetSuccessorsReply{}
	successorsCallOk := call(string(node.get_successor()), "ChordNode.GetSuccessors", &successorsArg, &successorsReply)
	if !successorsCallOk {
		fmt.Println("call to successor to get successors err: ", node.get_successor())
		return
	}
	node.mutex.Lock()
	copy(node.Successors[1:], successorsReply.Successors[:len(successorsReply.Successors)-1])
	node.mutex.Unlock()
}

func (node *ChordNode) GetPredecessor(arg *GetPredecessor, reply *GetPredecessorReply) error {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	reply.Address = node.Predecessor
	// fmt.Println("sending predecessor: ", reply.Address)
	return nil
}

func (node *ChordNode) GetSuccessors(arg *GetSuccessors, reply *GetSuccessorsReply) error {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	reply.Successors = node.Successors
	return nil
}

func (node *ChordNode) check_predecessor() {
	if node.Predecessor == "" {
		return
	}
	arg := GetPredecessor{}
	reply := GetPredecessorReply{}
	callOk := call(string(node.Predecessor), "ChordNode.GetPredecessor", &arg, &reply)
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

func (node *ChordNode) Notify(arg *Notify, reply *NotifyReply) error {
	id := bigInt_to_key(hashAddress(arg.Address))
	// fmt.Println("node.Predecessor: ", node.Predecessor)
	if node.Predecessor == "" || between(bigInt_to_key(hashAddress(node.Predecessor)), id, node.Id, false) {
		newMap := map[string][]byte{}
		reply.Bucket = newMap
		node.mutex.Lock()
		node.Predecessor = arg.Address
		pre_id := bigInt_to_key(hashAddress(arg.Address))
		for file, content := range node.Bucket {
			newMap[file] = content
			if !between(pre_id, bigInt_to_key(hashFileName(file)), node.Id, true) {
				delete(node.Bucket, file)
			}
		}
		if len(node.key) > 0 {
			reply.Key = node.key
		}
		node.mutex.Unlock()
		reply.Confirm = true
		if node.Address == node.get_successor() {
			node.mutex.Lock()
			node.Successors[0] = arg.Address
			node.mutex.Unlock()
		}
	} else {
		reply.Confirm = false
	}
	if node.Predecessor == arg.Address {
		node.mutex.Lock()
		pre_id := bigInt_to_key(hashAddress(node.Predecessor))
		node.ExtraBucket = map[string][]byte{}
		for file, content := range arg.Bucket {
			if between(pre_id, bigInt_to_key(hashFileName(file)), node.Id, true) {
				node.Bucket[file] = content
			} else {
				node.ExtraBucket[file] = content
			}
		}
		node.mutex.Unlock()
	}
	return nil
}

func (n *ChordNode) Put(args *Put, reply *PutReply) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	fmt.Println("put file: ", args.FileName)

	n.Bucket[args.FileName] = args.FileContent // security issue?
	reply.Confirm = true
	return nil
}

func (n *ChordNode) Get(args *Get, reply *GetReply) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	reply.Confirm = false
	val, ok := n.Bucket[args.FileName]
	// fmt.Println("get: ", args.FileName, " content: ", string(val))
	if ok {
		reply.Confirm = true
		reply.Content = val
	}

	return nil // security issue?
}

func (n *ChordNode) Delete(args *Delete, reply *DeleteReply) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	fmt.Println("delete: ", args.FileName)
	reply.Confirm = false
	_, ok := n.Bucket[args.FileName]
	if !ok {
		delete(n.Bucket, args.FileName)
		reply.Confirm = true
	}

	return nil
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

	bytes, r := aesEncyption(bytes, n.key)
	if r != nil {
		fmt.Println("ErrorEncyptio:", r)
	}
	// fmt.Println("this is the encrypted data:", bytes)

	arg := FindClosestSuccessor{Id: bigInt_to_key(hashFileName(fileName))}
	reply := FindClosestSuccessorReply{}
	n.Find_successor(&arg, &reply)

	if !reply.Ok {
		fmt.Println("could not find closest, try again!")
		return
	}
	putArgs := Put{FileName: fileName, FileContent: bytes}
	putReply := PutReply{}
	callOk := call(string(reply.Address), "ChordNode.Put", &putArgs, &putReply)

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
	arg := FindClosestSuccessor{Id: bigInt_to_key(hashFileName(fileName))}
	reply := FindClosestSuccessorReply{}
	n.Find_successor(&arg, &reply)

	if !reply.Ok {
		fmt.Println("could not find closest, try again!")
		return
	}
	getArgs := Get{FileName: fileName}
	getReply := GetReply{}
	callOk := call(string(reply.Address), "ChordNode.Get", &getArgs, &getReply)

	if !callOk {
		fmt.Println("call to get file on node failed: ", reply.Address)
		return
	}
	if !getReply.Confirm {
		fmt.Println("could not get file: ", fileName)
		return
	}

	orginalData, r := aesdecrption(getReply.Content, n.key)
	if r != nil {
		fmt.Println("Error decrypted data:", r)
		return
	}
	fmt.Println("this is the decrypted data:", orginalData)

	fmt.Println("Identifier: ", bigInt_to_key(hashAddress(reply.Address)), " Address: ", string(reply.Address), " Content: ", string(orginalData))
}

func (n *ChordNode) PrintState(args *Empty, reply *EmptyReply) error {
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

	return nil
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

	node.server()

	go node.background_stabilize()

	go node.background_fix_fingers()

	go node.background_check_predecessor()

	return &node
}

func (node *ChordNode) server() error {
	rpc.Register(node)
	rpc.HandleHTTP()

	l, e := net.Listen("tcp", string(node.Address))
	if e != nil {
		fmt.Println("unable to start node rpc server: ", e)
		return e
	}

	go http.Serve(l, nil)

	return nil
}

func call(address string, rpcname string, args interface{}, reply interface{}) bool {
	// fmt.Println("address: ", address)
	// fmt.Println("rpcname: ", rpcname)
	c, err := rpc.DialHTTP("tcp", address)
	if err != nil {
		fmt.Println("dialing error:", err)
		return false
	}
	defer c.Close()

	err = c.Call(rpcname, args, reply)
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

func key_to_bigInt(id Key) (*big.Int, bool) {
	value, ok := new(big.Int).SetString(string(id), 16)
	return value, ok
}

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
