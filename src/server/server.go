// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 GOTUNIX Networks <code@gotunix.net>
// SPDX-FileCopyrightText: 2026 Justin Ovens <code@gotunix.net>
// ----------------------------------------------------------------------------------------------- //
//                 $$$$$$\   $$$$$$\ $$$$$$$$\ $$\   $$\ $$\   $$\ $$$$$$\ $$\   $$\               //
//                $$  __$$\ $$  __$$\\__$$  __|$$ |  $$ |$$$\  $$ |\_$$  _|$$ |  $$ |              //
//                $$ /  \__|$$ /  $$ |  $$ |   $$ |  $$ |$$$$\ $$ |  $$ |  \$$\ $$  |              //
//                $$ |$$$$\ $$ |  $$ |  $$ |   $$ |  $$ |$$ $$\$$ |  $$ |   \$$$$  /               //
//                $$ |\_$$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ \$$$$ |  $$ |   $$  $$<                //
//                $$ |  $$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ |\$$$ |  $$ |  $$  /\$$\               //
//                \$$$$$$  | $$$$$$  |  $$ |   \$$$$$$  |$$ | \$$ |$$$$$$\ $$ /  $$ |              //
//                 \______/  \______/   \__|    \______/ \__|  \__|\______|\__|  \__|              //
// ----------------------------------------------------------------------------------------------- //
// Copyright (C) GOTUNIX Networks                                                                  //
// Copyright (C) Justin Ovens                                                                      //
// ----------------------------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify                            //
// it under the terms of the GNU Affero General Public License as                                  //
// published by the Free Software Foundation, either version 3 of the                              //
// License, or (at your option) any later version.                                                 //
//                                                                                                 //
// This program is distributed in the hope that it will be useful,                                 //
// but WITHOUT ANY WARRANTY; without even the implied warranty of                                  //
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   //
// GNU Affero General Public License for more details.                                             //
//                                                                                                 //
// You should have received a copy of the GNU Affero General Public License                        //
// along with this program.  If not, see <https://www.gnu.org/licenses/>.                          //
// ----------------------------------------------------------------------------------------------- //

package server

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"go-discord-notifications/bot"
	"go-discord-notifications/config"

	"github.com/bwmarrin/discordgo"
)

var severityMap = map[string]struct {
	Color  int
	Prefix string
}{
	"info":     {0x3498DB, "ℹ️  Info"},
	"success":  {0x2ECC71, "✅ Success"},
	"warning":  {0xE67E22, "⚠️  Warning"},
	"error":    {0xE74C3C, "❌ Error"},
	"critical": {0xFF0000, "🚨 Critical"},
}

var tailscaleSeverity = map[string]string{
	"tailnet-member-added":        "success",
	"tailnet-member-expired":      "warning",
	"tailnet-member-approved":     "success",
	"tailnet-member-removed":      "warning",
	"tailnet-member-updated":      "info",
	"node-created":                "success",
	"node-deleted":                "warning",
	"node-key-expiry-disabled":    "info",
	"node-key-expired":            "warning",
	"user-created":                "success",
	"user-deleted":                "warning",
	"user-approved":               "success",
	"user-suspended":              "error",
	"user-role-updated":           "info",
	"user-invited-to-tailnet":     "info",
	"dns-settings-updated":        "info",
	"acl-updated":                 "info",
	"acl-approved":                "success",
	"posture-integration-added":   "info",
	"posture-integration-removed": "warning",
}

var seerrConfig = map[string]struct {
	Color int
	Icon  string
}{
	"MEDIA_PENDING":       {0xE67E22, "⏳"},
	"MEDIA_APPROVED":      {0x2ECC71, "✅"},
	"MEDIA_AVAILABLE":     {0x2ECC71, "🍿"},
	"MEDIA_FAILED":        {0xE74C3C, "❌"},
	"MEDIA_DECLINED":      {0xE74C3C, "🚫"},
	"MEDIA_AUTO_APPROVED": {0x2ECC71, "🤖"},
	"MEMBER_JOINED":       {0x3498DB, "👋"},
	"ISSUE_CREATED":       {0xE67E22, "⚠️"},
	"ISSUE_RESOLVED":      {0x2ECC71, "✅"},
	"ISSUE_COMMENT":       {0x3498DB, "💬"},
	"TEST_NOTIFICATION":   {0x2ECC71, "🧪"},
}

func getMapValue(m map[string]interface{}, keys ...string) map[string]interface{} {
	for _, k := range keys {
		if v, ok := m[k].(map[string]interface{}); ok {
			return v
		}
	}
	return nil
}

func checkAuth(r *http.Request) error {
	if config.WebhookSecret == "" {
		return nil
	}

	queryToken := r.URL.Query().Get("token")
	if queryToken == "" {
		queryToken = r.URL.Query().Get("t")
	}

	if queryToken != "" {
		if hmac.Equal([]byte(queryToken), []byte(config.WebhookSecret)) {
			return nil
		}
		return fmt.Errorf("Invalid webhook secret in query")
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("Missing Authorization header or ?token parameter")
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if !hmac.Equal([]byte(token), []byte(config.WebhookSecret)) {
		return fmt.Errorf("Invalid webhook secret")
	}

	return nil
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := checkAuth(r); err != nil {
			log.Println("Auth failed:", err)
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, map[string]interface{}{
		"status":         "ok",
		"service":        "go-discord-notifier-webhook",
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"bot_loop_alive": bot.Session != nil,
	}, 200)
}

func notifyHandler(w http.ResponseWriter, r *http.Request) {
	var body interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendJSON(w, map[string]string{"error": "Request body must be valid JSON."}, 400)
		return
	}

	var events []map[string]interface{}
	switch v := body.(type) {
	case []interface{}:
		for _, e := range v {
			if emap, ok := e.(map[string]interface{}); ok {
				events = append(events, emap)
			}
		}
	case map[string]interface{}:
		events = append(events, v)
	}

	processedCount := 0
	for _, event := range events {
		descVal, ok := event["description"].(string)
		if !ok || strings.TrimSpace(descVal) == "" {
			continue
		}
		description := strings.TrimSpace(descVal)

		severity := "info"
		if srv, ok := event["severity"].(string); ok {
			severity = strings.ToLower(srv)
		}

		sevMap, ok := severityMap[severity]
		if !ok {
			sevMap = severityMap["info"]
		}

		title := sevMap.Prefix
		if tVal, ok := event["title"].(string); ok && strings.TrimSpace(tVal) != "" {
			title = strings.TrimSpace(tVal)
		}

		var channelID string
		if cv, ok := event["channel_id"].(string); ok {
			channelID = cv
		}

		var userIDs []string
		if uarr, ok := event["user_ids"].([]interface{}); ok {
			for _, u := range uarr {
				if us, ok := u.(string); ok {
					userIDs = append(userIDs, us)
				}
			}
		}

		bot.DispatchNotification(
			title,
			description,
			sevMap.Color,
			nil,
			fmt.Sprintf("Source: generic webhook • %s", time.Now().UTC().Format(time.RFC3339)),
			"",
			channelID,
			userIDs,
		)
		processedCount++
	}

	if processedCount == 0 {
		sendJSON(w, map[string]string{"error": "No valid events with 'description' found."}, 400)
		return
	}

	sendJSON(w, map[string]interface{}{"status": "queued", "processed_events": processedCount}, 200)
}

func tailscaleHandler(w http.ResponseWriter, r *http.Request) {
	var body interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendJSON(w, map[string]string{"error": "Request body must be valid JSON."}, 400)
		return
	}

	var events []map[string]interface{}
	switch v := body.(type) {
	case []interface{}:
		for _, e := range v {
			if emap, ok := e.(map[string]interface{}); ok {
				events = append(events, emap)
			}
		}
	case map[string]interface{}:
		events = append(events, v)
	}

	var processed []string
	for _, event := range events {
		eventType := "unknown"
		if ev, ok := event["type"].(string); ok {
			eventType = ev
		}

		tailnet := ""
		if t, ok := event["tailnet"].(string); ok {
			tailnet = t
		}

		message := ""
		if m, ok := event["message"].(string); ok {
			message = m
		}

		timestamp := time.Now().UTC().Format(time.RFC3339)
		if ts, ok := event["timestamp"].(string); ok {
			timestamp = ts
		}

		severity, ok := tailscaleSeverity[eventType]
		if !ok {
			severity = "info"
		}
		sevMap := severityMap[severity]

		// Capitalize first letter of replacement pattern
		title := fmt.Sprintf("🔒 Tailscale — %s", strings.ReplaceAll(eventType, "-", " "))
		description := message
		if description == "" {
			description = fmt.Sprintf("Event `%s` received from tailnet `%s`.", eventType, tailnet)
		}

		fields := []*discordgo.MessageEmbedField{
			{Name: "Event Type", Value: fmt.Sprintf("`%s`", eventType), Inline: true},
		}
		if tailnet != "" {
			fields = append(fields, &discordgo.MessageEmbedField{Name: "Tailnet", Value: tailnet, Inline: true})
		}
		fields = append(fields, &discordgo.MessageEmbedField{Name: "Event Time", Value: timestamp, Inline: false})

		bot.DispatchNotification(
			title,
			description,
			sevMap.Color,
			fields,
			fmt.Sprintf("Tailscale webhook • received %s", time.Now().UTC().Format(time.RFC3339)),
			"",
			"",
			nil,
		)
		processed = append(processed, eventType)
	}

	sendJSON(w, map[string]interface{}{"status": "queued", "processed_events": processed}, 200)
}

func seerrHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendJSON(w, map[string]string{"error": "Request body must be valid JSON."}, 400)
		return
	}

	notifType, _ := payload["notification_type"].(string)
	subject, _ := payload["subject"].(string)
	message, _ := payload["message"].(string)
	image, _ := payload["image"].(string)

	cfg, ok := seerrConfig[notifType]
	if !ok {
		cfg = struct {
			Color int
			Icon  string
		}{0x3498DB, "🔔"}
	}

	title := fmt.Sprintf("%s %s", cfg.Icon, subject)
	if subject == "" {
		title = fmt.Sprintf("%s Overseerr Notification", cfg.Icon)
	}

	var fields []*discordgo.MessageEmbedField

	// Media Info
	if media := getMapValue(payload, "media", "{{media}}"); media != nil {
		mType, _ := media["media_type"].(string)
		mStatus, _ := media["status"].(string)
		if mType != "" {
			fields = append(fields, &discordgo.MessageEmbedField{Name: "Type", Value: strings.Title(mType), Inline: true})
		}
		if mStatus != "" {
			fields = append(fields, &discordgo.MessageEmbedField{Name: "Status", Value: mStatus, Inline: true})
		}
	}

	// Request Info
	if request := getMapValue(payload, "request", "{{request}}"); request != nil {
		user, _ := request["requestedBy_username"].(string)
		if user != "" {
			fields = append(fields, &discordgo.MessageEmbedField{Name: "Requested By", Value: user, Inline: true})
		}
	}

	// Issue Info
	if issue := getMapValue(payload, "issue", "{{issue}}"); issue != nil {
		iType, _ := issue["issue_type"].(string)
		iStatus, _ := issue["issue_status"].(string)
		if iType != "" {
			fields = append(fields, &discordgo.MessageEmbedField{Name: "Issue Type", Value: iType, Inline: true})
		}
		if iStatus != "" {
			fields = append(fields, &discordgo.MessageEmbedField{Name: "Issue Status", Value: iStatus, Inline: true})
		}
	}

	// Dynamic Routing
	var channelID string
	if cid, ok := payload["channel_id"].(string); ok {
		channelID = cid
	}

	var userIDs []string
	if uids, ok := payload["user_ids"].([]interface{}); ok {
		for _, u := range uids {
			if us, ok := u.(string); ok {
				userIDs = append(userIDs, us)
			}
		}
	} else if uid, ok := payload["user_id"].(string); ok {
		userIDs = append(userIDs, uid)
	}

	bot.DispatchNotification(
		title,
		message,
		cfg.Color,
		fields,
		fmt.Sprintf("Overseerr • %s", time.Now().UTC().Format(time.RFC3339)),
		image,
		channelID,
		userIDs,
	)

	sendJSON(w, map[string]string{"status": "queued"}, 200)
}

func customHandler(w http.ResponseWriter, r *http.Request) {
	var body interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendJSON(w, map[string]string{"error": "Request body must be valid JSON."}, 400)
		return
	}

	var events []map[string]interface{}
	switch v := body.(type) {
	case []interface{}:
		for _, e := range v {
			if emap, ok := e.(map[string]interface{}); ok {
				events = append(events, emap)
			}
		}
	case map[string]interface{}:
		events = append(events, v)
	}

	processedCount := 0
	for _, event := range events {
		titleVal, titleOk := event["title"].(string)
		descVal, descOk := event["description"].(string)
		if !titleOk || !descOk || strings.TrimSpace(titleVal) == "" || strings.TrimSpace(descVal) == "" {
			continue
		}

		title := strings.TrimSpace(titleVal)
		description := strings.TrimSpace(descVal)

		color := 0x5865F2
		if cVal, ok := event["color"].(float64); ok {
			color = int(cVal)
		} else if cStr, ok := event["color"].(string); ok {
			fmt.Sscanf(cStr, "%d", &color)
		}

		var fields []*discordgo.MessageEmbedField
		if fArr, ok := event["fields"].([]interface{}); ok {
			for _, f := range fArr {
				if fTuple, ok := f.([]interface{}); ok && len(fTuple) >= 2 {
					name, nOk := fTuple[0].(string)
					val, vOk := fTuple[1].(string)
					if nOk && vOk {
						inline := true
						if len(fTuple) > 2 {
							if in, ok := fTuple[2].(bool); ok {
								inline = in
							}
						}
						fields = append(fields, &discordgo.MessageEmbedField{Name: name, Value: val, Inline: inline})
					}
				}
			}
		}

		var footer string
		if ft, ok := event["footer"].(string); ok {
			footer = ft
		}

		var channelID string
		if cv, ok := event["channel_id"].(string); ok {
			channelID = cv
		}

		var userIDs []string
		if uarr, ok := event["user_ids"].([]interface{}); ok {
			for _, u := range uarr {
				if us, ok := u.(string); ok {
					userIDs = append(userIDs, us)
				}
			}
		}

		bot.DispatchNotification(title, description, color, fields, footer, "", channelID, userIDs)
		processedCount++
	}

	if processedCount == 0 {
		sendJSON(w, map[string]string{"error": "No valid custom events found."}, 400)
		return
	}

	sendJSON(w, map[string]interface{}{"status": "queued", "processed_events": processedCount}, 200)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	bot.DispatchNotification(
		"🧪 Test Notification",
		"Webhook pipeline is working correctly in Golang.",
		0x2ECC71,
		[]*discordgo.MessageEmbedField{
			{Name: "Server", Value: fmt.Sprintf("%s:%s", config.ServerHost, config.ServerPort), Inline: true},
			{Name: "Auth", Value: "Enabled", Inline: true},
			{Name: "Time", Value: time.Now().UTC().Format(time.RFC3339), Inline: false},
		},
		"Triggered via GET /webhook/test",
		"",
		"",
		nil,
	)
	sendJSON(w, map[string]interface{}{"status": "queued", "message": "Test notification fired."}, 200)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s - %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/webhook/notify", requireAuth(notifyHandler))
	mux.HandleFunc("/webhook/tailscale", requireAuth(tailscaleHandler))
	mux.HandleFunc("/webhook/seerr", requireAuth(seerrHandler))
	mux.HandleFunc("/webhook/custom", requireAuth(customHandler))
	mux.HandleFunc("/webhook/test", requireAuth(testHandler))

	addr := fmt.Sprintf("%s:%s", config.ServerHost, config.ServerPort)
	log.Printf("Golang webhook server listening on http://%s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
