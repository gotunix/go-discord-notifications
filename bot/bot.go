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

package bot

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"go-discord-notifications/config"
)

var Session *discordgo.Session

func Start() error {
	var err error
	Session, err = discordgo.New("Bot " + config.DiscordBotToken)
	if err != nil {
		return err
	}

	Session.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsDirectMessages | discordgo.IntentMessageContent | discordgo.IntentGuilds

	Session.AddHandler(onReady)
	Session.AddHandler(onMessageCreate)

	err = Session.Open()
	if err != nil {
		return err
	}

	return nil
}

func Stop() {
	if Session != nil {
		Session.Close()
	}
}

func onReady(s *discordgo.Session, event *discordgo.Ready) {
	log.Printf("Logged in as %s (id=%s)", s.State.User.String(), s.State.User.ID)
	
	s.UpdateGameStatus(0, "for webhook events — !help")
}

func isAllowedUser(userID string) bool {
	if len(config.AllowedUserIDs) == 0 {
		return true
	}
	for _, uid := range config.AllowedUserIDs {
		if uid == userID {
			return true
		}
	}
	return false
}

func onMessageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}

	if m.GuildID == "" && !strings.HasPrefix(m.Content, "!") {
		log.Printf("DM from %s (%s): %s", m.Author.String(), m.Author.ID, m.Content)
		return
	}

	if !strings.HasPrefix(m.Content, "!") {
		return
	}

	if m.GuildID != "" {
		s.ChannelMessageSend(m.ChannelID, "⚠️  This command only works in Direct Messages.")
		return
	}

	if !isAllowedUser(m.Author.ID) {
		s.ChannelMessageSend(m.ChannelID, "🚫 You are not authorised to use this bot.")
		return
	}

	args := strings.Split(m.Content, " ")
	cmd := args[0]

	switch cmd {
	case "!help":
		cmdHelp(s, m)
	case "!status":
		cmdStatus(s, m)
	case "!ping":
		cmdPing(s, m)
	case "!say":
		cmdSay(s, m, args[1:])
	case "!dm":
		cmdDm(s, m, args)
	case "!channel":
		cmdChannel(s, m, args)
	case "!targets":
		cmdTargets(s, m)
	}
}

func BuildEmbed(title, description string, color int, fields []*discordgo.MessageEmbedField, footer string) *discordgo.MessageEmbed {
	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	if fields != nil {
		embed.Fields = fields
	}
	if footer != "" {
		embed.Footer = &discordgo.MessageEmbedFooter{Text: footer}
	}
	return embed
}

func cmdHelp(s *discordgo.Session, m *discordgo.MessageCreate) {
	embed := BuildEmbed(
		"🤖 Discord Notifier Bot",
		"I accept commands via **Direct Message**. I also forward incoming webhook events to Discord.",
		0x5865F2,
		[]*discordgo.MessageEmbedField{
			{Name: "!help", Value: "This help message", Inline: false},
			{Name: "!status", Value: "Show bot & server status", Inline: false},
			{Name: "!ping", Value: "Check bot latency", Inline: false},
			{Name: "!say <message>", Value: "Post a message to the notification channel", Inline: false},
			{Name: "!dm <uid> <msg>", Value: "Send a DM to a Discord user by ID", Inline: false},
			{Name: "!channel <id> <message>", Value: "Post to an arbitrary channel by ID", Inline: false},
			{Name: "!targets", Value: "Show configured notification targets", Inline: false},
		},
		"Commands work in DMs only.",
	)
	s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func cmdPing(s *discordgo.Session, m *discordgo.MessageCreate) {
	latencyMs := s.HeartbeatLatency().Milliseconds()
	s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🏓 Pong! Latency: **%d ms**", latencyMs))
}

func cmdStatus(s *discordgo.Session, m *discordgo.MessageCreate) {
	channelInfo := "_not configured_"
	if config.NotifyChannelID != "" {
		channelInfo = fmt.Sprintf("<#%s> (`%s`)", config.NotifyChannelID, config.NotifyChannelID)
	}
	
	dmTargets := "_none_"
	if len(config.NotifyUserIDs) > 0 {
		var uids []string
		for _, u := range config.NotifyUserIDs {
			uids = append(uids, fmt.Sprintf("`%s`", u))
		}
		dmTargets = strings.Join(uids, ", ")
	}

	authStatus := "⚠️ Disabled"
	if config.WebhookSecret != "" {
		authStatus = "✅ Enabled"
	}

	userCount := len(s.State.Guilds)

	embed := BuildEmbed(
		"📊 Bot Status",
		"Current configuration and connectivity.",
		0x2ECC71,
		[]*discordgo.MessageEmbedField{
			{Name: "Bot User", Value: s.State.User.String(), Inline: true},
			{Name: "Latency", Value: fmt.Sprintf("%d ms", s.HeartbeatLatency().Milliseconds()), Inline: true},
			{Name: "Guilds", Value: fmt.Sprintf("%d", userCount), Inline: true},
			{Name: "Notify Channel", Value: channelInfo, Inline: false},
			{Name: "Notify DM Targets", Value: dmTargets, Inline: false},
			{Name: "Webhook Server", Value: fmt.Sprintf("`%s:%s`", config.ServerHost, config.ServerPort), Inline: false},
			{Name: "Webhook Auth", Value: authStatus, Inline: true},
		},
		"",
	)
	s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func cmdSay(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
	if config.NotifyChannelID == "" {
		s.ChannelMessageSend(m.ChannelID, "❌ `NOTIFY_CHANNEL_ID` is not configured.")
		return
	}
	
	msg := strings.Join(args, " ")
	_, err := s.ChannelMessageSend(config.NotifyChannelID, msg)
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, "❌ Could not send message to channel.")
	} else {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Message sent to <#%s>.", config.NotifyChannelID))
	}
}

func cmdDm(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
	if len(args) < 3 {
		s.ChannelMessageSend(m.ChannelID, "❌ Usage: !dm <uid> <msg>")
		return
	}
	uid := args[1]
	msg := strings.Join(args[2:], " ")

	ch, err := s.UserChannelCreate(uid)
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Could not create DM with user ID `%s`: %v", uid, err))
		return
	}
	_, err = s.ChannelMessageSend(ch.ID, msg)
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, "❌ Could not send message. They may have DMs disabled.")
	} else {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ DM sent to user (`%s`).", uid))
	}
}

func cmdChannel(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
	if len(args) < 3 {
		s.ChannelMessageSend(m.ChannelID, "❌ Usage: !channel <id> <msg>")
		return
	}
	cid := args[1]
	msg := strings.Join(args[2:], " ")
	
	_, err := s.ChannelMessageSend(cid, msg)
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Could not find or post to channel `%s`.", cid))
	} else {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Message sent to <#%s>.", cid))
	}
}

func cmdTargets(s *discordgo.Session, m *discordgo.MessageCreate) {
	var lines []string
	if config.NotifyChannelID != "" {
		lines = append(lines, fmt.Sprintf("📢 Channel: <#%s>", config.NotifyChannelID))
	}
	for _, uid := range config.NotifyUserIDs {
		lines = append(lines, fmt.Sprintf("💬 DM user: `%s`", uid))
	}
	if len(lines) == 0 {
		lines = append(lines, "_No targets configured._")
	}
	s.ChannelMessageSend(m.ChannelID, strings.Join(lines, "\n"))
}

func DispatchNotification(title, description string, color int, fields []*discordgo.MessageEmbedField, footer, channelID string, userIDs []string) {
	if Session == nil {
		log.Println("Bot session not initialized — cannot dispatch notification.")
		return
	}

	finalFooter := footer
	if finalFooter == "" {
		finalFooter = "Discord Notifier • via webhook"
	}

	embed := BuildEmbed(title, description, color, fields, finalFooter)

	targetChannelID := channelID
	if targetChannelID == "" {
		targetChannelID = config.NotifyChannelID
	}

	targetUserIDs := userIDs
	if len(targetUserIDs) == 0 {
		targetUserIDs = config.NotifyUserIDs
	}
	if len(targetUserIDs) == 0 {
		targetUserIDs = config.AllowedUserIDs
	}

	if targetChannelID != "" {
		_, err := Session.ChannelMessageSendEmbed(targetChannelID, embed)
		if err != nil {
			log.Printf("Failed to send to channel %s: %v\n", targetChannelID, err)
		} else {
			log.Printf("Notification sent to channel %s\n", targetChannelID)
		}
	}

	for _, uid := range targetUserIDs {
		ch, err := Session.UserChannelCreate(uid)
		if err != nil {
			log.Printf("Failed to create DM channel for user %s: %v\n", uid, err)
			continue
		}
		_, err = Session.ChannelMessageSendEmbed(ch.ID, embed)
		if err != nil {
			log.Printf("Failed to DM user %s: %v\n", uid, err)
		} else {
			log.Printf("Notification DM sent to user %s\n", uid)
		}
	}
}
