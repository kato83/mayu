package notification

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
)

// mockSMTPServer starts a minimal SMTP server for testing.
// It records received messages and supports optional STARTTLS advertisement.
type mockSMTPServer struct {
	listener net.Listener
	addr     string
	wg       sync.WaitGroup
	messages []mockMessage
	mu       sync.Mutex
}

type mockMessage struct {
	from string
	to   []string
	data string
}

func newMockSMTPServer(t *testing.T) *mockSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &mockSMTPServer{
		listener: ln,
		addr:     ln.Addr().String(),
	}
	s.wg.Add(1)
	go s.serve(t)
	return s
}

func (s *mockSMTPServer) serve(t *testing.T) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed
		}
		s.wg.Add(1)
		go s.handleConn(t, conn)
	}
}

func (s *mockSMTPServer) handleConn(t *testing.T, conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	write := func(msg string) {
		_, _ = conn.Write([]byte(msg + "\r\n"))
	}

	write("220 localhost mock SMTP")

	var msg mockMessage
	var inData bool
	var dataLines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				inData = false
				msg.data = strings.Join(dataLines, "\r\n")
				s.mu.Lock()
				s.messages = append(s.messages, msg)
				s.mu.Unlock()
				msg = mockMessage{}
				dataLines = nil
				write("250 OK")
				continue
			}
			dataLines = append(dataLines, line)
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			write("250-localhost")
			write("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			msg.from = extractAddr(line)
			write("250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			msg.to = append(msg.to, extractAddr(line))
			write("250 OK")
		case upper == "DATA":
			inData = true
			write("354 Go ahead")
		case upper == "QUIT":
			write("221 Bye")
			return
		case strings.HasPrefix(upper, "AUTH"):
			write("235 Authentication successful")
		default:
			write("250 OK")
		}
	}
}

func extractAddr(line string) string {
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start >= 0 && end > start {
		return line[start+1 : end]
	}
	// Fallback: take everything after the colon.
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return line
}

func (s *mockSMTPServer) close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func TestEmailSender_Send(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	sender := &EmailSender{
		Host:     host,
		Port:     port,
		Username: "user",
		Password: "pass",
		From:     "mayu@example.com",
		TLS:      false,
	}

	ctx := context.Background()
	err := sender.Send(ctx, []string{"alert@example.com"}, "Test Alert", "<h1>Hello</h1>")
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(srv.messages))
	}

	msg := srv.messages[0]
	if msg.from != "mayu@example.com" {
		t.Errorf("from = %q, want %q", msg.from, "mayu@example.com")
	}
	if len(msg.to) != 1 || msg.to[0] != "alert@example.com" {
		t.Errorf("to = %v, want [alert@example.com]", msg.to)
	}
	if !strings.Contains(msg.data, "Subject: Test Alert") {
		t.Errorf("data missing subject: %s", msg.data)
	}
	if !strings.Contains(msg.data, "<h1>Hello</h1>") {
		t.Errorf("data missing HTML body: %s", msg.data)
	}
	if !strings.Contains(msg.data, "Content-Type: text/html") {
		t.Errorf("data missing Content-Type header: %s", msg.data)
	}
}

func TestEmailSender_Send_NoRecipients(t *testing.T) {
	sender := &EmailSender{
		Host: "localhost",
		Port: 25,
		From: "mayu@example.com",
	}
	err := sender.Send(context.Background(), nil, "test", "body")
	if err == nil {
		t.Fatal("expected error for no recipients")
	}
	if !strings.Contains(err.Error(), "no recipients") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEmailSender_Send_NoHost(t *testing.T) {
	sender := &EmailSender{
		Port: 25,
		From: "mayu@example.com",
	}
	err := sender.Send(context.Background(), []string{"a@b.com"}, "test", "body")
	if err == nil {
		t.Fatal("expected error for no host")
	}
	if !strings.Contains(err.Error(), "SMTP host is not configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEmailSender_Send_MultipleRecipients(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	sender := &EmailSender{
		Host: host,
		Port: port,
		From: "mayu@example.com",
		TLS:  false,
	}

	ctx := context.Background()
	recipients := []string{"a@example.com", "b@example.com", "c@example.com"}
	err := sender.Send(ctx, recipients, "Multi", "<p>multi</p>")
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(srv.messages))
	}
	if len(srv.messages[0].to) != 3 {
		t.Errorf("expected 3 recipients, got %d", len(srv.messages[0].to))
	}
}

func TestBuildMIMEMessage(t *testing.T) {
	msg := string(buildMIMEMessage("from@test.com", []string{"to@test.com"}, "Test Subject", "<p>body</p>"))

	checks := []string{
		"From: from@test.com",
		"To: to@test.com",
		"Subject: Test Subject",
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=\"UTF-8\"",
		"<p>body</p>",
	}
	for _, check := range checks {
		if !strings.Contains(msg, check) {
			t.Errorf("message missing %q:\n%s", check, msg)
		}
	}
}
