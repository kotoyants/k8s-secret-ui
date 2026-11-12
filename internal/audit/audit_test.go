package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLog(t *testing.T) {
	var buf bytes.Buffer
	a := New(slog.New(slog.NewJSONHandler(&buf, nil)))
	a.Log(t.Context(), Event{
		ActorID: 7, ActorEmail: "a@x.com", Action: ActionLogin,
		TargetType: "user", TargetID: "7", IP: "10.0.0.1",
		Details: map[string]any{"created": true},
	})

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v: %s", err, buf.String())
	}
	want := map[string]any{
		"msg": "audit", "audit": true, "action": "login", "result": "success",
		"actor_id": float64(7), "actor_email": "a@x.com", "target_type": "user",
		"target_id": "7", "ip": "10.0.0.1",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if d, _ := got["details"].(map[string]any); d["created"] != true {
		t.Errorf("details = %v", got["details"])
	}
}

func TestLogOmitsEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	New(slog.New(slog.NewJSONHandler(&buf, nil))).Log(t.Context(), Event{Action: ActionLogout})
	var got map[string]any
	_ = json.Unmarshal(buf.Bytes(), &got)
	for _, k := range []string{"actor_id", "actor_email", "target_type", "ip", "details"} {
		if _, ok := got[k]; ok {
			t.Errorf("unexpected field %s", k)
		}
	}
}
