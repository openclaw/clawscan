package runner

import (
	"bytes"
	"encoding/json"
)

const childProgressLineLimit = 64 * 1024
const childProgressEventLimit = 512

type childProgressWriter struct {
	progress *runProgress
	ready    chan struct{}
	pid      int
	line     []byte
	oversize bool
	sequence int
}

func newChildProgressWriter(progress *runProgress, env map[string]string) *childProgressWriter {
	if progress == nil || env["CLAWSCAN_CHILD_PROGRESS"] != "1" {
		return nil
	}
	progress.mutex.Lock()
	defer progress.mutex.Unlock()
	if progress.phase != "judge" {
		return nil
	}
	return &childProgressWriter{progress: progress, ready: make(chan struct{})}
}

func (writer *childProgressWriter) start(pid int) {
	writer.pid = pid
	close(writer.ready)
}

func (writer *childProgressWriter) Write(data []byte) (int, error) {
	<-writer.ready
	size := len(data)
	for len(data) > 0 && writer.sequence <= childProgressEventLimit {
		end := bytes.IndexByte(data, '\n')
		fragment := data
		if end >= 0 {
			fragment = data[:end]
		}
		if !writer.oversize {
			if len(writer.line)+len(fragment) > childProgressLineLimit {
				writer.line = nil
				writer.oversize = true
			} else {
				writer.line = append(writer.line, fragment...)
			}
		}
		if end < 0 {
			break
		}
		writer.finishLine()
		data = data[end+1:]
	}
	return size, nil
}

func (writer *childProgressWriter) finish() {
	if len(writer.line) > 0 || writer.oversize {
		writer.finishLine()
	}
}

func (writer *childProgressWriter) finishLine() {
	defer func() {
		writer.line = writer.line[:0]
		writer.oversize = false
	}()
	if writer.sequence > childProgressEventLimit {
		return
	}
	event := progressEvent{Event: "child_event"}
	if writer.sequence == childProgressEventLimit {
		event.Event = "child_event_limit"
	} else if writer.oversize {
		event.Event = "child_event_dropped"
	} else {
		var record struct {
			Type string `json:"type"`
			Item struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"item"`
		}
		if json.Unmarshal(writer.line, &record) != nil {
			return
		}
		switch record.Type {
		case "thread.started", "turn.started", "turn.completed", "turn.failed", "error":
			event.ChildEvent = record.Type
		case "item.started", "item.updated", "item.completed":
			switch record.Item.Type {
			case "command_execution", "reasoning", "agent_message", "file_change", "mcp_tool_call", "collab_tool_call", "web_search", "todo_list", "error":
				event.ChildItem = record.Item.Type
			default:
				return
			}
			event.ChildEvent = record.Type
			switch record.Item.Status {
			case "in_progress", "completed", "failed", "declined":
				event.ChildState = record.Item.Status
			}
		default:
			return
		}
	}
	writer.sequence++
	event.Sequence = writer.sequence
	event.PID = writer.pid
	writer.progress.emit(event)
}
