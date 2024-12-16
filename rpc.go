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
}

type NotifyReply struct {
	Confirm bool
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
	Id Key
}

type Get_reply struct {
	Content string
	Confirm bool
}

type Put struct {
	Id    Key
	Value string
}

type Put_reply struct {
	Confirm bool
}

type Delete struct {
	Id Key
}

type Delete_reply struct {
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
