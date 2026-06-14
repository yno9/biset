package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"biset/vault"
)

var feedParser = gofeed.NewParser()

func fetchFeed(feedURL string, state FeedState, relayname string) ([]vault.Message, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	feed, err := feedParser.ParseURLWithContext(feedURL, ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", feedURL, err)
	}

	name := state.Name
	if name == "" {
		name = feed.Title
	}

	seenSet := make(map[string]bool, len(state.SeenGUIDs))
	for _, g := range state.SeenGUIDs {
		seenSet[g] = true
	}

	domain := feedDomain(feedURL)
	mailboxID := vault.MakeMailboxID(relayname + "/")
	threadID := vault.MakeThreadID(feedURL)

	var msgs []vault.Message
	var newGUIDs []string

	items := feed.Items

	for _, item := range items {
		guid := itemGUID(item)
		if seenSet[guid] {
			continue
		}
		newGUIDs = append(newGUIDs, guid)

		pub := itemPubDate(item)
		msgID := vault.MakeMessageID(guid, relayname, pub)

		body := buildBody(item)

		msgs = append(msgs, vault.NewTextMessage(
			msgID,
			threadID,
			mailboxID,
			[]*vault.Address{{Email: domain, Name: item.Title}},
			[]*vault.Address{{Email: relayname}},
			nil,
			name,
			body,
			pub,
			"",
		))
	}

	return msgs, newGUIDs, nil
}

func itemGUID(item *gofeed.Item) string {
	if item.GUID != "" {
		return item.GUID
	}
	if item.Link != "" {
		return item.Link
	}
	h := sha256.Sum256([]byte(item.Title + item.Published))
	return fmt.Sprintf("%x", h[:8])
}

func itemPubDate(item *gofeed.Item) time.Time {
	if item.PublishedParsed != nil {
		return *item.PublishedParsed
	}
	if item.UpdatedParsed != nil {
		return *item.UpdatedParsed
	}
	return time.Now()
}

func buildBody(item *gofeed.Item) string {
	var parts []string
	parts = append(parts, item.Title)
	if item.Link != "" {
		parts = append(parts, item.Link)
	}
	content := item.Content
	if content == "" {
		content = item.Description
	}
	content = strings.TrimSpace(content)
	if content != "" {
		parts = append(parts, content)
	}
	return strings.Join(parts, "\n\n")
}

func feedDomain(feedURL string) string {
	u, err := url.Parse(feedURL)
	if err != nil {
		return feedURL
	}
	return u.Hostname()
}
