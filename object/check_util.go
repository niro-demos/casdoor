// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"regexp"
	"strconv"
	"time"

	"github.com/casdoor/casdoor/i18n"
)

var reRealName *regexp.Regexp

func init() {
	var err error
	reRealName, err = regexp.Compile("^[\u4E00-\u9FA5]{2,3}(?:·[\u4E00-\u9FA5]{2,3})*$")
	if err != nil {
		panic(err)
	}
}

func isValidRealName(s string) bool {
	return reRealName.MatchString(s)
}

func resetUserSigninErrorTimes(user *User) error {
	// if the password is correct and wrong times is not zero, reset the error times
	if user.SigninWrongTimes == 0 {
		return nil
	}

	user.SigninWrongTimes = 0
	_, err := UpdateUser(user.GetId(), user, []string{"signin_wrong_times", "last_signin_wrong_time"}, false)
	return err
}

func GetFailedSigninConfigByUser(user *User) (int, int, error) {
	application, err := GetApplicationByUser(user)
	if err != nil {
		return 0, 0, err
	}
	if application == nil {
		return 0, 0, fmt.Errorf("the application for user %s is not found", user.GetId())
	}

	failedSigninLimit := application.FailedSigninLimit
	if failedSigninLimit == 0 {
		failedSigninLimit = DefaultFailedSigninLimit
	}

	failedSigninFrozenTime := application.FailedSigninFrozenTime
	if failedSigninFrozenTime == 0 {
		failedSigninFrozenTime = DefaultFailedSigninFrozenTime
	}

	return failedSigninLimit, failedSigninFrozenTime, nil
}

func recordSigninErrorInfo(user *User, lang string, options ...bool) error {
	enableCaptcha := false
	if len(options) > 0 {
		enableCaptcha = options[0]
	}

	failedSigninLimit, failedSigninFrozenTime, errSignin := GetFailedSigninConfigByUser(user)
	if errSignin != nil {
		return errSignin
	}

	// increase failed login count, and record the lockout time only when first reaching the limit
	if user.SigninWrongTimes < failedSigninLimit {
		user.SigninWrongTimes++
		if user.SigninWrongTimes >= failedSigninLimit {
			user.LastSigninWrongTime = time.Now().UTC().Format(time.RFC3339)
		}
	}

	// update user
	_, err := UpdateUser(user.GetId(), user, []string{"signin_wrong_times", "last_signin_wrong_time"}, false)
	if err != nil {
		return err
	}

	return signinErrorInfoMessage(user.SigninWrongTimes, failedSigninLimit, failedSigninFrozenTime, enableCaptcha, lang)
}

// signinErrorInfoMessage builds the "remaining chances"/"please wait" error a user
// sees after a wrong credential, given the current failed-attempt state. It is the
// pure decision half of recordSigninErrorInfo, extracted so the wrong-credential
// invariant (a warning after N failures, then a timed lockout) can be asserted
// without a database round-trip. Keep it in sync with recordSigninErrorInfo.
func signinErrorInfoMessage(signinWrongTimes, failedSigninLimit, failedSigninFrozenTime int, enableCaptcha bool, lang string) error {
	leftChances := failedSigninLimit - signinWrongTimes
	if leftChances == 0 && enableCaptcha {
		return newSigninError(SigninReasonWrongPassword, i18n.Translate(lang, "check:password or code is incorrect"))
	} else if leftChances >= 0 {
		return newSigninError(SigninReasonWrongPassword, fmt.Sprintf(i18n.Translate(lang, "check:password or code is incorrect, you have %s remaining chances"), strconv.Itoa(leftChances)))
	}

	// don't show the chance error message if the user has no chance left
	return newSigninError(SigninReasonAccountFrozen, fmt.Sprintf(i18n.Translate(lang, "check:You have entered the wrong password or code too many times, please wait for %d minutes and try again"), failedSigninFrozenTime))
}

// mfaAttemptOutcome is the pure decision produced by evalMfaSigninAttempt for one
// login-time second-factor attempt. persist reports whether SigninWrongTimes /
// LastSigninWrongTime on the user were mutated and must be written back; err is the
// user-facing result (nil = accept the login, otherwise the freeze / "remaining
// chances" message, matching the password path).
type mfaAttemptOutcome struct {
	persist bool
	err     error
}

// evalMfaSigninAttempt is the pure, database-free core of the login-time second-factor
// (MFA) rate limit: it applies the same failed-attempt bookkeeping the password step
// uses, mutating the passed-in user's SigninWrongTimes / LastSigninWrongTime in memory
// and returning what the caller should surface and whether to persist.
//
//   - frozen (SigninWrongTimes at/over the limit and still inside the cooldown): the
//     attempt is refused before verifyErr is even considered — this is what stops the
//     brute force; the crypto check must not be consulted while frozen.
//   - cooldown elapsed: the counter is reset first, then the attempt is evaluated fresh.
//   - verifyErr != nil (wrong passcode): increment the counter and return the escalating
//     "remaining chances" → "please wait" message.
//   - verifyErr == nil (correct passcode): accept and clear the counter.
//
// Keeping this logic pure lets the security invariant (a warning after N wrong second-
// factor guesses, then a timed lockout, with a correct code still accepted on an
// un-frozen session) be asserted without a database. now is injected for determinism.
func evalMfaSigninAttempt(user *User, verifyErr error, failedSigninLimit, failedSigninFrozenTime int, enableCaptcha bool, now time.Time, lang string) mfaAttemptOutcome {
	// 1. Freeze pre-check: while frozen, refuse regardless of passcode correctness.
	if user.SigninWrongTimes >= failedSigninLimit {
		lastSignWrongTime, _ := time.Parse(time.RFC3339, user.LastSigninWrongTime)
		minutes := failedSigninFrozenTime - int(now.Sub(lastSignWrongTime).Minutes())
		if minutes > 0 {
			return mfaAttemptOutcome{persist: false, err: newSigninError(SigninReasonAccountFrozen, fmt.Sprintf(i18n.Translate(lang, "check:You have entered the wrong password or code too many times, please wait for %d minutes and try again"), minutes))}
		}
		// cooldown elapsed: reset and evaluate this attempt fresh.
		user.SigninWrongTimes = 0
	}

	// 2. Correct passcode: accept, clearing any accumulated failures.
	if verifyErr == nil {
		if user.SigninWrongTimes == 0 {
			return mfaAttemptOutcome{persist: false, err: nil}
		}
		user.SigninWrongTimes = 0
		return mfaAttemptOutcome{persist: true, err: nil}
	}

	// 3. Wrong passcode: count it and return the escalating warning / lockout message.
	if user.SigninWrongTimes < failedSigninLimit {
		user.SigninWrongTimes++
		if user.SigninWrongTimes >= failedSigninLimit {
			user.LastSigninWrongTime = now.Format(time.RFC3339)
		}
	}
	return mfaAttemptOutcome{persist: true, err: signinErrorInfoMessage(user.SigninWrongTimes, failedSigninLimit, failedSigninFrozenTime, enableCaptcha, lang)}
}

// CheckMfaSigninErrorTimes gates a login-time second-factor (MFA) verification with
// the same per-user failed-attempt bookkeeping the password step uses, keyed on the
// session-bound user. It (1) refuses further attempts while the user is frozen,
// (2) runs the supplied verification, (3) on failure increments SigninWrongTimes and
// returns the "remaining chances"/"please wait" message, and (4) on success resets
// the counter. Without this, the 6-digit TOTP second factor can be brute-forced with
// unlimited guesses. verify performs only the crypto check (e.g. mfaUtil.Verify).
func CheckMfaSigninErrorTimes(user *User, verify func() error, lang string) error {
	failedSigninLimit, failedSigninFrozenTime, err := GetFailedSigninConfigByUser(user)
	if err != nil {
		return err
	}

	// Only consult the crypto check when the user is not already frozen; a frozen
	// pre-check must short-circuit so a locked-out attacker can't keep guessing.
	verifyErr := error(nil)
	if !(user.SigninWrongTimes >= failedSigninLimit && withinFrozenWindow(user, failedSigninFrozenTime, time.Now().UTC())) {
		verifyErr = verify()
	}

	outcome := evalMfaSigninAttempt(user, verifyErr, failedSigninLimit, failedSigninFrozenTime, false, time.Now().UTC(), lang)
	if outcome.persist {
		if _, updateErr := UpdateUser(user.GetId(), user, []string{"signin_wrong_times", "last_signin_wrong_time"}, false); updateErr != nil {
			return updateErr
		}
	}
	return outcome.err
}

// withinFrozenWindow reports whether the user is currently inside the post-lockout
// cooldown, so the crypto verification can be skipped entirely while frozen.
func withinFrozenWindow(user *User, failedSigninFrozenTime int, now time.Time) bool {
	lastSignWrongTime, _ := time.Parse(time.RFC3339, user.LastSigninWrongTime)
	return failedSigninFrozenTime-int(now.Sub(lastSignWrongTime).Minutes()) > 0
}
