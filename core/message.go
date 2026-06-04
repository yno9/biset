package core

import (
	"fmt"
	"sort"
	"strings"
)

type Message struct {
	From      string            `json:"from"`
	Body      string            `json:"body"`
	Ts        int64             `json:"ts"`
	MessageID string            `json:"message_id,omitempty"`
	ParentID  string            `json:"parent_id,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	Seen      bool              `json:"seen"`
}

type Thread struct {
	ID       string
	Messages []Message
}

type Action string

const (
	ActionSend    Action = "send"
	ActionDelete  Action = "deleted"
	ActionArchive Action = "archived"
	ActionSpam    Action = "spam"
)

const (
	MetaFromName     = "from_name"
	MetaSubject      = "subject"
	MetaToAddrs      = "to_addrs"
	MetaCcAddrs      = "cc_addrs"
	MetaMyRole       = "my_role"
	MetaAPID         = "ap_id"
	MetaPGPEncrypted = "pgp_encrypted"
)

func GroupThreads(messages []Message) []Thread {
	byID := map[string]*Message{}
	for i := range messages {
		if messages[i].MessageID != "" {
			byID[messages[i].MessageID] = &messages[i]
		}
	}

	threadID := func(m Message) string {
		root := resolveRoot(m.MessageID, m.ParentID, byID, 20)
		if root != "" {
			return root
		}
		return fmt.Sprintf("ts-%d", m.Ts)
	}

	threads := map[string]*Thread{}
	order := []string{}
	for _, m := range messages {
		tid := threadID(m)
		if _, ok := threads[tid]; !ok {
			threads[tid] = &Thread{ID: tid}
			order = append(order, tid)
		}
		threads[tid].Messages = append(threads[tid].Messages, m)
	}

	result := make([]Thread, 0, len(threads))
	for _, tid := range order {
		t := threads[tid]
		sort.Slice(t.Messages, func(i, j int) bool {
			return t.Messages[i].Ts > t.Messages[j].Ts
		})
		result = append(result, *t)
	}

	sort.Slice(result, func(i, j int) bool {
		return LatestTs(result[i]) > LatestTs(result[j])
	})

	return result
}

func resolveRoot(msgID, parentID string, byID map[string]*Message, depth int) string {
	if parentID == "" {
		return msgID
	}
	if depth <= 0 {
		return parentID
	}
	parent, ok := byID[parentID]
	if !ok {
		return parentID
	}
	return resolveRoot(parent.MessageID, parent.ParentID, byID, depth-1)
}

func LatestTs(t Thread) int64 {
	var max int64
	for _, m := range t.Messages {
		if m.Ts > max {
			max = m.Ts
		}
	}
	return max
}

func SafeFilename(s string) string {
	rep := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")
	s = rep.Replace(s)
	if len(s) > 60 {
		s = s[:60]
	}
	return strings.TrimSpace(s)
}
