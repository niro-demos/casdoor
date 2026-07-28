// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/xorm/names"
)

func TestConcurrentSignupConsumesSingleUseInvitationAtomically(t *testing.T) {
	setupInvitationSignupTestStore(t)

	organization := &Organization{
		Owner:        "admin",
		Name:         "signup-race-org",
		PasswordType: "plain",
		AccountItems: []*AccountItem{},
	}
	if _, err := ormer.Engine.Insert(organization); err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	application := &Application{
		Owner:        "admin",
		Name:         "signup-race-app",
		Organization: organization.Name,
		EnableSignUp: true,
		SignupItems: []*SignupItem{
			{Name: "Username", Visible: true, Required: true},
			{Name: "Password", Visible: true, Required: true},
			{Name: "Invitation code", Visible: true, Required: true},
		},
	}
	if _, err := ormer.Engine.Insert(application); err != nil {
		t.Fatalf("insert application: %v", err)
	}

	invitation := &Invitation{
		Owner:       organization.Name,
		Name:        "single-use",
		DisplayName: "single-use",
		Code:        "SingleUseCode",
		DefaultCode: "SingleUseCode",
		Quota:       1,
		UsedCount:   0,
		Application: application.Name,
		State:       "Active",
	}
	if _, err := AddInvitation(invitation, "en"); err != nil {
		t.Fatalf("insert invitation: %v", err)
	}

	const workers = 8
	checked := make(chan *signupRaceAttempt, workers)
	resume := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			authForm := &form.AuthForm{
				Application:    application.Name,
				Organization:   organization.Name,
				Username:       fmt.Sprintf("race-user-%d", i),
				Name:           fmt.Sprintf("race-user-%d", i),
				Password:       "ProofPassRace1!",
				InvitationCode: invitation.Code,
			}
			checkedInvitation, msg := CheckInvitationCode(application, organization, authForm, "en")
			attempt := &signupRaceAttempt{
				authForm:   authForm,
				invitation: checkedInvitation,
				checkMsg:   msg,
			}
			checked <- attempt
			<-resume
		}()
	}

	attempts := make([]*signupRaceAttempt, 0, workers)
	for i := 0; i < workers; i++ {
		attempts = append(attempts, <-checked)
	}

	for _, attempt := range attempts {
		if attempt.checkMsg != "" {
			t.Fatalf("signup setup did not reach the race window: %s", attempt.checkMsg)
		}
		if attempt.invitation == nil {
			t.Fatalf("signup setup did not load the invitation")
		}
	}

	close(resume)
	wg.Wait()

	successes := 0
	for _, attempt := range attempts {
		attempt.err = addSignupUserWithInvitation(organization, application, attempt.authForm, attempt.invitation)
		if attempt.err != nil {
			continue
		}
		successes++
	}
	if successes != 1 {
		t.Fatalf("single-use invitation allowed %d successful signup attempts; want exactly 1", successes)
	}

	var createdUsers []User
	if err := ormer.Engine.Where("owner = ?", organization.Name).Find(&createdUsers); err != nil {
		t.Fatalf("count created users: %v", err)
	}
	storedInvitation, err := GetInvitation(invitation.GetId())
	if err != nil {
		t.Fatalf("reload invitation: %v", err)
	}
	if storedInvitation == nil {
		t.Fatalf("invitation disappeared")
	}

	if len(createdUsers) > invitation.Quota {
		t.Fatalf("single-use invitation created %d accounts; want at most %d (usedCount=%d)", len(createdUsers), invitation.Quota, storedInvitation.UsedCount)
	}
	if storedInvitation.UsedCount != len(createdUsers) {
		t.Fatalf("invitation usedCount=%d, created users=%d; want them equal", storedInvitation.UsedCount, len(createdUsers))
	}
}

type signupRaceAttempt struct {
	authForm   *form.AuthForm
	invitation *Invitation
	checkMsg   string
	err        error
}

func setupInvitationSignupTestStore(t *testing.T) {
	t.Helper()

	if err := web.LoadAppConfig("ini", "../conf/app.conf"); err != nil {
		t.Fatalf("load config: %v", err)
	}

	adapter, err := NewAdapter("sqlite", filepath.Join(t.TempDir(), "casdoor.db"), "")
	if err != nil {
		t.Fatalf("new sqlite adapter: %v", err)
	}
	adapter.Engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	ormer = adapter
	t.Cleanup(func() {
		ormer.close()
		ormer = nil
	})

	ormer.createTable()
}

func addSignupUserWithInvitation(organization *Organization, application *Application, authForm *form.AuthForm, invitation *Invitation) error {
	user := &User{
		Owner:             authForm.Organization,
		Name:              authForm.Username,
		CreatedTime:       util.GetCurrentTime(),
		Id:                util.GenerateId(),
		Type:              "normal-user",
		Password:          authForm.Password,
		DisplayName:       authForm.Name,
		Avatar:            organization.DefaultAvatar,
		Address:           []string{},
		SignupApplication: application.Name,
		Properties:        map[string]string{},
		Invitation:        invitation.Name,
		InvitationCode:    authForm.InvitationCode,
		RegisterType:      "Application Signup",
		RegisterSource:    fmt.Sprintf("%s/%s", authForm.Organization, application.Name),
	}

	_, err := AddSignupUser(user, application, organization, authForm, invitation, "en")
	return err
}
