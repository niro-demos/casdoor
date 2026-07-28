// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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
	"context"
	"fmt"
	"slices"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

var (
	CasdoorApplication  = "app-built-in"
	CasdoorOrganization = "built-in"
)

type Session struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	Application string `xorm:"varchar(100) notnull pk" json:"application"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	SessionId []string `json:"sessionId"`

	ExclusiveSignin bool `xorm:"-"`
}

// GetMaskedSession redacts the session's raw SessionId values -- the
// literal beego session-store key, which is the exact value beego issues as
// the casdoor_session_id cookie and is therefore directly replayable to
// fully authenticate as the session's owner without their password --
// unless the caller is the session's own owner or a global admin. This
// mirrors the GetMaskedToken pattern used for other bearer-credential-
// bearing objects: non-secret metadata (owner, name, application,
// createdTime) stays visible so admin session-management UIs (list, count,
// delete-the-whole-record) keep working, but the raw credential is never
// exposed to a caller who isn't the session's owner or a global admin.
func GetMaskedSession(session *Session, isOwnerOrGlobalAdmin bool) *Session {
	if session == nil || isOwnerOrGlobalAdmin {
		return session
	}

	for i := range session.SessionId {
		session.SessionId[i] = "***"
	}

	return session
}

// GetMaskedSessions redacts raw session ids on every session in a listing.
// Listing endpoints (GetSessions/GetPaginationSessions) can return sessions
// belonging to many different users in the caller's organization, so --
// like GetMaskedTokens does for Token listings -- they always mask,
// regardless of the caller's own privilege level.
func GetMaskedSessions(sessions []*Session) []*Session {
	for _, session := range sessions {
		GetMaskedSession(session, false)
	}
	return sessions
}

func GetSessions(owner string) ([]*Session, error) {
	sessions := []*Session{}
	var err error
	if owner != "" {
		err = ormer.Engine.Desc("created_time").Where("owner = ?", owner).Find(&sessions)
	} else {
		err = ormer.Engine.Desc("created_time").Find(&sessions)
	}
	if err != nil {
		return sessions, err
	}

	return sessions, nil
}

func GetUserSessions(owner string, name string) ([]*Session, error) {
	sessions := []*Session{}

	err := ormer.Engine.Desc("created_time").Where("owner = ? and name = ?", owner, name).Find(&sessions)
	if err != nil {
		return sessions, err
	}

	return sessions, nil
}

func GetUserAppSessions(owner string, name string, application string) ([]*Session, error) {
	sessions := []*Session{}

	err := ormer.Engine.Desc("created_time").Where("owner = ? and name = ? and application = ?", owner, name, application).Find(&sessions)
	if err != nil {
		return sessions, err
	}

	return sessions, nil
}

func GetPaginationSessions(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Session, error) {
	sessions := []*Session{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&sessions)
	if err != nil {
		return sessions, err
	}

	return sessions, nil
}

func GetSessionCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Session{})
}

func GetSingleSession(id string) (*Session, error) {
	owner, name, application := util.GetOwnerAndNameAndOtherFromId(id)
	session := Session{Owner: owner, Name: name, Application: application}
	get, err := ormer.Engine.Get(&session)
	if err != nil {
		return &session, err
	}

	if !get {
		return nil, nil
	}

	return &session, nil
}

func UpdateSession(id string, session *Session) (bool, error) {
	owner, name, application := util.GetOwnerAndNameAndOtherFromId(id)

	if ss, err := GetSingleSession(id); err != nil {
		return false, err
	} else if ss == nil {
		return false, nil
	}

	affected, err := ormer.Engine.ID(core.PK{owner, name, application}).Update(session)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func removeExtraSessionIds(session *Session) {
	if len(session.SessionId) > 100 {
		session.SessionId = session.SessionId[(len(session.SessionId) - 100):]
	}
}

func AddSession(session *Session) (bool, error) {
	dbSession, err := GetSingleSession(session.GetId())
	if err != nil {
		return false, err
	}

	if dbSession == nil {
		session.CreatedTime = util.GetCurrentTime()

		affected, err := ormer.Engine.Insert(session)
		if err != nil {
			return false, err
		}

		return affected != 0, nil
	} else {
		m := make(map[string]struct{})
		for _, v := range dbSession.SessionId {
			m[v] = struct{}{}
		}
		for _, v := range session.SessionId {
			if _, exists := m[v]; !exists {
				dbSession.SessionId = append(dbSession.SessionId, v)
			}
		}

		removeExtraSessionIds(dbSession)

		if session.ExclusiveSignin {
			dbSession.SessionId = []string{session.SessionId[0]}
		}

		return UpdateSession(dbSession.GetId(), dbSession)
	}
}

func DeleteSession(id, curSessionId string) (bool, error) {
	owner, name, application := util.GetOwnerAndNameAndOtherFromId(id)
	if owner == CasdoorOrganization && application == CasdoorApplication {
		session, err := GetSingleSession(id)
		if err != nil {
			return false, err
		}

		// If session doesn't exist, return success with no rows affected
		// This is a valid state (e.g., when a user has no active session)
		if session == nil {
			return false, nil
		}

		if slices.Contains(session.SessionId, curSessionId) {
			return false, fmt.Errorf("session:session id %s is the current session and cannot be deleted", curSessionId)
		}

		DeleteBeegoSession(session.SessionId)
	}

	affected, err := ormer.Engine.ID(core.PK{owner, name, application}).Delete(&Session{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteAllUserSessions(owner string, name string) (bool, error) {
	affected, err := ormer.Engine.Where("owner = ? and name = ?", owner, name).Delete(&Session{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteSessionId(id string, sessionId string) (bool, error) {
	session, err := GetSingleSession(id)
	if err != nil {
		return false, err
	}
	if session == nil {
		return false, nil
	}

	owner, _, application := util.GetOwnerAndNameAndOtherFromId(id)
	if owner == CasdoorOrganization && application == CasdoorApplication {
		DeleteBeegoSession([]string{sessionId})
	}

	session.SessionId = util.DeleteVal(session.SessionId, sessionId)
	if len(session.SessionId) == 0 {
		return DeleteSession(id, "")
	} else {
		return UpdateSession(id, session)
	}
}

func DeleteBeegoSession(sessionIds []string) {
	for _, sessionId := range sessionIds {
		err := web.GlobalSessions.GetProvider().SessionDestroy(context.Background(), sessionId)
		if err != nil {
			return
		}
	}
}

func (session *Session) GetId() string {
	return fmt.Sprintf("%s/%s/%s", session.Owner, session.Name, session.Application)
}

func IsSessionDuplicated(id string, sessionId string) (bool, error) {
	session, err := GetSingleSession(id)
	if err != nil {
		return false, err
	}

	if session == nil {
		return false, nil
	} else {
		if len(session.SessionId) > 1 {
			return true, nil
		} else if len(session.SessionId) < 1 {
			return false, nil
		} else {
			return session.SessionId[0] != sessionId, nil
		}
	}
}
