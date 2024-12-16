package main

type SuccFind struct {
	Id string
}

type Bingo struct {
	Identified bool
	SuccId     NodeAddress
}

type FindClosestSuccessor struct {
	Id Key
}

type FindClosestSuccessorReply struct {
	Address NodeAddress
	Ok      bool
}

type Notify struct {
	Address NodeAddress
	Bucket  map[string][]byte
}

type NotifyReply struct {
	Confirm bool
	Bucket  map[string][]byte
	Key     []byte
}

type GetPredecessor struct {
}

type GetPredecessorReply struct {
	Address NodeAddress
}

type GetSuccessors struct {
}

type GetSuccessorsReply struct {
	Successors []NodeAddress
}

type Get struct {
	FileName string
}

type GetReply struct {
	Content []byte
	Confirm bool
}

type Put struct {
	FileName    string
	FileContent []byte
}

type PutReply struct {
	Confirm bool
}

type Delete struct {
	FileName string
}

type DeleteReply struct {
	Confirm bool
}

type Empty struct {
}
type EmptyReply struct {
}

// type Bucket struct {
//     Id    string
//     Value string
// }

// type Bucket_reply struct {
//     confirm bool
//     Content string
// }
