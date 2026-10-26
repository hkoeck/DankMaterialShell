pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Services.Pam
import qs.Common
import qs.Services

Scope {
    id: root

    readonly property var log: Log.scoped("Pam")

    property bool lockSecured: false
    // the deliberate "I am here to unlock" gesture: a click on the shield or the first
    // keystroke. GNOME opens its pam conversation at exactly this point, not on lock.
    property bool inputRevealed: false
    property bool unlockInProgress: false

    readonly property alias passwd: passwd
    readonly property alias fprint: fprint
    readonly property alias u2f: u2f
    property string lockMessage
    property string state
    property string fprintState
    property string u2fState
    property bool u2fPending: false
    property string u2fPendingMode
    property string buffer

    // the prompt pam asked for, e.g. "PIN: "
    property string authPromptText: ""
    property bool responseSubmitted: false
    property bool awaitingUserInput: false
    property bool responseInFlight: false
    // the conversation is held open while the user types, so passwd.active is not "busy"
    readonly property bool authBusy: passwd.active && root.responseInFlight
    // prompts seen in the current conversation; the first one keeps what was typed
    property int promptsSeen: 0
    // answers sent in the current conversation; a success without one came from a module
    // that authenticated on its own
    property int promptsAnswered: 0
    // a conversation nobody asked for may discover the prompt, but it may not unlock:
    // only one started by a deliberate unlock intent is allowed to succeed passively
    property bool passiveUnlockAllowed: false
    // reopens per lock without a prompt in between, so a stack that fails without ever
    // asking anything is not reopened forever
    property int autoRestartCount: 0
    readonly property int maxAutoRestarts: 3
    property bool bufferWasEmpty: true
    property var attemptInfoMessages: []
    property bool lockoutAnnouncedThisAttempt: false

    signal flashMsg
    signal unlockRequested

    function resetAuthFlows(): void {
        passwd.abort();
        fprint.stop();
        u2f.abort();
        u2fErrorRetry.running = false;
        u2fPendingTimeout.running = false;
        passwdActiveTimeout.running = false;
        unlockRequestTimeout.running = false;
        root.u2fPending = false;
        root.u2fPendingMode = "";
        root.u2fState = "";
        root.unlockInProgress = false;
    }

    function recoverFromAuthStall(newState: string): void {
        resetAuthFlows();
        root.state = newState;
        flashMsg();
        stateReset.restart();
        fprint.checkAvail();
        u2f.checkAvail();
    }

    // The conversation is opened as soon as the screen is locked, like hyprlock's auth thread
    // and gnome's unlock dialog: pam is asked, the first prompt is held unanswered, and the
    // field can show what it actually asked for instead of guessing "Password".
    // allowPassiveUnlock says whether this conversation may complete on its own - see
    // passiveUnlockAllowed. Nothing is submitted here, so no attempt is consumed.
    function beginAuthSession(allowPassiveUnlock: bool): void {
        if (passwd.active || root.unlockInProgress || !root.lockSecured)
            return;
        // the security key owns the attempt while it waits for a touch
        if (root.u2fPending)
            return;
        // a stack that can authenticate on its own is only run on a submit
        if (!root.mayOpenUnrequestedSession)
            return;
        root.passiveUnlockAllowed = allowPassiveUnlock === true;
        root.responseSubmitted = false;
        root.awaitingUserInput = false;
        root.responseInFlight = false;
        root.promptsAnswered = 0;
        passwd.start();
    }

    // Someone is here and wants in: an open conversation may now succeed on its own, so a
    // configured face or fingerprint module unlocks as intended - just not from locking.
    function noteUnlockIntent(): void {
        // intent is recorded even where no conversation may be opened ahead of a
        // submit: what it says is that the next success was asked for
        root.passiveUnlockAllowed = true;
        if (!passwd.active)
            root.beginAuthSession(true);
    }

    onInputRevealedChanged: {
        if (root.inputRevealed)
            root.noteUnlockIntent();
    }

    // the stack is read asynchronously, so it can still be unknown when the screen
    // locks; the prompt is worth a second look once it arrives
    onMayOpenUnrequestedSessionChanged: {
        if (root.mayOpenUnrequestedSession && root.lockSecured && !root.unlockInProgress && !passwd.active)
            eagerStart.restart();
    }

    // typing after a conversation ended (a failed attempt) has to reopen it
    onBufferChanged: {
        const wasEmpty = root.bufferWasEmpty;
        root.bufferWasEmpty = root.buffer.length === 0;
        if (wasEmpty && root.buffer.length > 0)
            root.noteUnlockIntent();
    }

    function submitPassword(): void {
        root.responseSubmitted = true;
        root.passiveUnlockAllowed = true;
        if (!passwd.active) {
            passwd.start();
            return;
        }
        if (passwd.responseRequired) {
            root.responseSubmitted = false;
            root.awaitingUserInput = false;
            root.responseInFlight = true;
            root.promptsAnswered = root.promptsAnswered + 1;
            passwdActiveTimeout.restart();
            passwd.respond(root.buffer);
        } else {
            // kept and sent when the prompt arrives; a stack that never asks still times out
            passwdActiveTimeout.restart();
        }
    }

    function completeUnlock(): void {
        if (!root.unlockInProgress) {
            root.unlockInProgress = true;
            passwd.abort();
            fprint.stop();
            u2f.abort();
            u2fErrorRetry.running = false;
            u2fPendingTimeout.running = false;
            root.u2fPending = false;
            root.u2fPendingMode = "";
            root.u2fState = "";
            unlockRequestTimeout.restart();
            unlockRequested();
        }
    }

    function proceedAfterPrimaryAuth(): void {
        if (!root.u2fSuppressedByPrimaryPam && SettingsData.enableU2f && SettingsData.u2fMode === "and" && u2f.available) {
            u2f.startForSecondFactor();
        } else {
            if (AdminPolicy.disableCustomLockPam && SettingsData.enableU2f && SettingsData.u2fMode === "and" && !u2fConfigWatcher.loaded)
                log.warn("/etc/pam.d/dankshell-u2f is missing, unlocking without the security key");
            completeUnlock();
        }
    }

    function cancelU2fPending(): void {
        if (!root.u2fPending)
            return;
        u2f.abort();
        u2fErrorRetry.running = false;
        u2fPendingTimeout.running = false;
        root.u2fPending = false;
        root.u2fPendingMode = "";
        root.u2fState = "";
        fprint.checkAvail();
    }

    readonly property bool customPamActive: SettingsData.lockPamPath !== "" && customPamWatcher.loaded
    readonly property bool fprintSuppressedByPrimaryPam: !AdminPolicy.disableCustomLockPam && (SettingsData.lockPamExternallyManaged || (customPamActive && SettingsData.lockPamInlineFprint))
    readonly property bool u2fSuppressedByPrimaryPam: !AdminPolicy.disableCustomLockPam && (SettingsData.lockPamExternallyManaged || (customPamActive && SettingsData.lockPamInlineU2f))
    readonly property bool customU2fPamActive: SettingsData.lockU2fPamPath !== "" && customU2fPamWatcher.loaded

    FileView {
        id: customPamWatcher

        path: SettingsData.lockPamPath !== "" ? SettingsData.lockPamPath : ""
        printErrors: false
    }

    FileView {
        id: dankshellConfigWatcher

        path: "/etc/pam.d/dankshell"
        printErrors: false
    }

    FileView {
        id: u2fConfigWatcher

        path: "/etc/pam.d/dankshell-u2f"
        watchChanges: true
        printErrors: false
    }

    FileView {
        id: fprintConfigWatcher

        path: AdminPolicy.disableCustomLockPam ? "/etc/pam.d/dankshell-fprint" : ""
        printErrors: false
    }

    FileView {
        id: customU2fPamWatcher

        path: SettingsData.lockU2fPamPath !== "" ? SettingsData.lockU2fPamPath : ""
        printErrors: false
    }

    // Whether the stack the password context will talk to carries a module that can
    // authenticate on its own. Resolved by `dms auth validate`, which walks the
    // includes properly (nested, cycle-safe) instead of guessing from the file here.
    property bool primaryPamKnown: false
    property bool primaryPamHasExternalAuth: false

    // The service or path the password context resolves to, in the form the CLI wants.
    readonly property var primaryPamQuery: {
        if (AdminPolicy.disableCustomLockPam)
            return ["--service", dankshellConfigWatcher.loaded ? "dankshell" : "login"];
        if (root.customPamActive)
            return ["--path", SettingsData.lockPamPath];
        if (SettingsData.lockPamExternallyManaged)
            return ["--service", "login"];
        if (dankshellConfigWatcher.loaded)
            return ["--service", "dankshell"];
        if (userPamWatcher.loaded)
            return ["--path", root.userPamDir + "/dankshell"];
        // the bundled assets/pam/login: pam_unix and nothing else
        return [];
    }

    // The settings can point the password context at another stack at any time, so an
    // answer is only good for the question it was asked.
    readonly property string primaryPamQueryKey: root.primaryPamQuery.join(" ")
    property string inspectedQueryKey: ""

    onPrimaryPamQueryChanged: root.inspectPrimaryPam()

    function inspectPrimaryPam(): void {
        if (root.primaryPamQuery.length === 0) {
            root.inspectedQueryKey = "";
            root.primaryPamHasExternalAuth = false;
            root.primaryPamKnown = true;
            return;
        }
        root.primaryPamKnown = false;
        if (inspectPrimaryPamProcess.running)
            inspectPrimaryPamProcess.running = false;
        root.inspectedQueryKey = root.primaryPamQueryKey;
        inspectPrimaryPamProcess.command = ["dms", "auth", "validate", "--purpose", "password", "--json"].concat(root.primaryPamQuery);
        inspectPrimaryPamProcess.running = true;
    }

    Process {
        id: inspectPrimaryPamProcess

        running: false
        stdout: StdioCollector {
            onStreamFinished: {
                // the question changed while this one was in flight
                if (root.inspectedQueryKey !== root.primaryPamQueryKey) {
                    root.inspectPrimaryPam();
                    return;
                }
                try {
                    const report = JSON.parse(text);
                    // A dms that predates inlineFaceAuth cannot answer the question, and
                    // silence is not a no: without it a face stack would look safe.
                    if (!("inlineFaceAuth" in report)) {
                        root.log.warn("This dms does not report face auth modules; leaving the conversation to a submit");
                        root.primaryPamHasExternalAuth = true;
                        root.primaryPamKnown = true;
                        return;
                    }
                    root.primaryPamHasExternalAuth = report.inlineFingerprint === true || report.inlineU2f === true || report.inlineFaceAuth === true;
                    root.primaryPamKnown = true;
                } catch (e) {
                    // an unreadable answer is treated like a stack that can self-authenticate
                    root.log.warn("Could not read the lock PAM report:", e);
                    root.primaryPamKnown = false;
                }
            }
        }
        onExited: exitCode => {
            if (exitCode !== 0 && !root.primaryPamKnown)
                root.log.warn("dms auth validate failed, leaving the conversation to a submit");
        }
    }

    // Opening a conversation runs every module in the stack, so on a stack with a
    // biometric or token module it costs a face scan or a reader touch the moment the
    // screen locks - for a result that is then discarded. There the conversation waits
    // for a submit, exactly as it did before. Until the stack is known the same applies.
    // See #3775.
    readonly property bool mayOpenUnrequestedSession: root.primaryPamKnown && !root.primaryPamHasExternalAuth

    // Fallback stack written by `dms auth resolve-lock` when no managed
    // /etc/pam.d/dankshell exists. See #2789.
    readonly property string userPamDir: Paths.strip(Paths.state) + "/pam"

    FileView {
        id: userPamWatcher

        path: root.userPamDir + "/dankshell"
        printErrors: false
    }

    Process {
        id: resolveUserPam

        command: ["dms", "auth", "resolve-lock", "--quiet"]
        running: false
        onExited: exitCode => {
            if (exitCode === 0)
                userPamWatcher.reload();
        }
    }

    function ensureUserPamConfig(): void {
        if (AdminPolicy.disableCustomLockPam || SettingsData.lockPamExternallyManaged || resolveUserPam.running)
            return;
        resolveUserPam.running = true;
    }

    Component.onCompleted: {
        ensureUserPamConfig();
        inspectPrimaryPam();
    }

    PamContext {
        id: passwd

        config: {
            if (AdminPolicy.disableCustomLockPam)
                return dankshellConfigWatcher.loaded ? "dankshell" : "login";
            if (root.customPamActive)
                return SettingsData.lockPamPath.slice(SettingsData.lockPamPath.lastIndexOf("/") + 1);
            if (SettingsData.lockPamExternallyManaged)
                return "login";
            if (dankshellConfigWatcher.loaded)
                return "dankshell";
            if (userPamWatcher.loaded)
                return "dankshell";
            return "login";
        }
        configDirectory: {
            if (AdminPolicy.disableCustomLockPam)
                return "/etc/pam.d";
            if (root.customPamActive) {
                const idx = SettingsData.lockPamPath.lastIndexOf("/");
                return idx > 0 ? SettingsData.lockPamPath.slice(0, idx) : "/";
            }
            if (SettingsData.lockPamExternallyManaged)
                return "/etc/pam.d";
            if (dankshellConfigWatcher.loaded)
                return "/etc/pam.d";
            if (userPamWatcher.loaded)
                return root.userPamDir;
            return Quickshell.shellDir + "/assets/pam";
        }

        onMessageChanged: {
            // collected by position, not text, so it works in any locale
            if (message.length > 0 && !responseRequired)
                root.attemptInfoMessages = root.attemptInfoMessages.concat([message]);
        }

        // not responseRequiredChanged: that only fires on change, so two prompts in
        // a row leave the second unhandled
        onPamMessage: {
            if (!responseRequired)
                return;

            root.authPromptText = (message || "").replace(/:\s*$/, "").trim();
            root.promptsSeen = root.promptsSeen + 1;
            // a prompt that arrives is proof the stack asks something
            root.autoRestartCount = 0;

            const notice = root.attemptInfoMessages.filter(m => m !== message);
            if (notice.length > 0) {
                root.lockMessage = notice.join("\n");
                root.lockoutAnnouncedThisAttempt = true;
            }
            root.attemptInfoMessages = [];

            // each prompt needs its own submission, or the second gets the first answer
            if (root.responseSubmitted) {
                root.responseSubmitted = false;
                root.awaitingUserInput = false;
                root.responseInFlight = true;
                root.promptsAnswered = root.promptsAnswered + 1;
                respond(root.buffer);
            } else {
                root.awaitingUserInput = true;
                root.responseInFlight = false;
                passwdActiveTimeout.running = false;
            }
        }

        onCompleted: res => {
            // requisite preauth can lock without ever prompting; surface it here too
            if (!root.lockoutAnnouncedThisAttempt) {
                if (root.attemptInfoMessages.length > 0) {
                    root.lockMessage = root.attemptInfoMessages.join("\n");
                    root.lockoutAnnouncedThisAttempt = true;
                } else {
                    root.lockMessage = "";
                }
                root.attemptInfoMessages = [];
            }

            if (res === PamResult.Success) {
                // A stack can authenticate without ever asking (face, fingerprint). In a
                // conversation that only exists to learn the prompt, that is not an unlock
                // request, so it is dropped and the screen stays locked. The next intent
                // signal opens a conversation that is allowed to succeed this way.
                if (root.promptsAnswered === 0 && !root.passiveUnlockAllowed) {
                    root.log.info("Discarding unrequested authentication success");
                    root.responseInFlight = false;
                    root.awaitingUserInput = false;
                    return;
                }
                if (!root.unlockInProgress) {
                    fprint.stop();
                    root.proceedAfterPrimaryAuth();
                }
                return;
            }

            unlockRequestTimeout.running = false;
            root.unlockInProgress = false;
            root.u2fPending = false;
            root.u2fPendingMode = "";
            root.u2fState = "";
            u2fPendingTimeout.running = false;
            u2f.abort();

            if (res === PamResult.Error)
                root.state = "error";
            else if (res === PamResult.MaxTries)
                root.state = "max";
            else if (res === PamResult.Failed)
                root.state = "fail";

            root.responseSubmitted = false;
            root.responseInFlight = false;
            root.flashMsg();
            stateReset.restart();
        }
    }

    Connections {
        target: passwd

        function onActiveChanged() {
            root.authPromptText = "";
            root.awaitingUserInput = false;
            root.promptsSeen = 0;
            if (!passwd.active)
                root.promptsAnswered = 0;
            if (passwd.active) {
                root.attemptInfoMessages = [];
                root.lockoutAnnouncedThisAttempt = false;
                if (root.responseSubmitted)
                    passwdActiveTimeout.restart();
                else
                    passwdActiveTimeout.running = false;
            } else {
                root.responseInFlight = false;
                passwdActiveTimeout.running = false;
                // A failed attempt ends the conversation, and with it the prompt: the
                // field would fall back to "Password..." while pam is going to ask for
                // the PIN again. Reopening it is what keeps the label honest, and it
                // may no more unlock by itself than the one opened at lock time.
                if (root.lockSecured && !root.unlockInProgress && !root.u2fPending && root.autoRestartCount < root.maxAutoRestarts) {
                    root.autoRestartCount = root.autoRestartCount + 1;
                    authRestart.restart();
                }
            }
        }
    }

    PamContext {
        id: fprint

        readonly property bool available: SettingsData.lockFingerprintReady && (!AdminPolicy.disableCustomLockPam || fprintConfigWatcher.loaded)
        property int tries: 0
        property int errorTries: 0
        property double attemptStartedAt: 0
        property bool completedDuringStart: false
        readonly property int maxErrorTries: 200
        readonly property int daemonIdleExitMs: 30000
        // sessionTimeoutMs mirrors `timeout=` in assets/pam/fprint; under the
        // policy, /etc/pam.d/dankshell-fprint must carry the same value
        readonly property int sessionTimeoutMs: 90000
        readonly property int verifyStartSlackMs: 10000
        readonly property bool retrying: errorRetry.running
        readonly property int retryInterval: errorRetry.interval
        readonly property bool allowed: available && SettingsData.enableFprint && root.lockSecured && !root.fprintSuppressedByPrimaryPam && !root.unlockInProgress && !root.u2fPending && !SessionService.preparingForSleep && !SessionService.sleepRequested && !IdleService.monitorsOff && tries < SettingsData.maxFprintTries
        readonly property string status: {
            if (!available || !SettingsData.enableFprint || !root.lockSecured || root.fprintSuppressedByPrimaryPam)
                return "disabled";
            if (tries >= SettingsData.maxFprintTries)
                return "max";
            if (!allowed)
                return "paused";
            if (active)
                return "active";
            if (retrying)
                return "retrying";
            return errorTries >= maxErrorTries ? "stopped" : "idle";
        }

        function stop(): void {
            errorRetry.stop();
            attemptStartedAt = 0;
            abort();
        }

        // pam_fprintd reports an expired timeout as PAM_AUTHINFO_UNAVAIL, the same
        // result a device fault gives, and its "Verification timed out" message is
        // translated, so age is the signal we can rely on. Its timeout runs from the
        // verify rather than from the claim, which is why the age is measured from
        // the message announcing the verify: a slow claim then cannot make a fault
        // look old enough, and a session that never reached a verify never qualifies.
        // That message lands after pam_fprintd has already armed its deadline, so the
        // age read here runs short of the real timeout and the slack makes it up. The
        // bias is deliberate: a timeout misread as a fault parks the reader behind the
        // backoff, while a fault misread as a timeout costs one extra retry.
        function attemptSettled(): bool {
            return attemptStartedAt > 0 && Date.now() - attemptStartedAt >= sessionTimeoutMs - verifyStartSlackMs;
        }

        function checkAvail(): void {
            if (!allowed) {
                stop();
                return;
            }
            if (!active && !retrying)
                startAttempt();
        }

        function startAttempt(): void {
            if (!allowed || errorTries >= maxErrorTries) {
                stop();
                return;
            }
            if (active)
                return;
            errorRetry.stop();
            if (root.fprintState === "error")
                root.fprintState = "";
            attemptStartedAt = 0;
            completedDuringStart = false;
            if (start())
                return;
            if (!completedDuringStart)
                scheduleErrorRetry();
        }

        function scheduleErrorRetry(): void {
            stop();
            if (!allowed)
                return;
            errorTries++;
            root.fprintState = "error";
            if (errorTries === 1)
                root.flashMsg();
            fprintStateReset.restart();
            if (errorTries < maxErrorTries)
                errorRetry.restart();
        }

        function recover(): void {
            if (!allowed)
                return;
            errorTries = 0;
            if (!active)
                startAttempt();
        }

        onAllowedChanged: {
            if (!allowed)
                stop();
            else
                Qt.callLater(checkAvail);
        }

        config: AdminPolicy.disableCustomLockPam ? "dankshell-fprint" : "fprint"
        configDirectory: AdminPolicy.disableCustomLockPam ? "/etc/pam.d" : Quickshell.shellDir + "/assets/pam"

        onPamMessage: {
            if (attemptStartedAt === 0)
                attemptStartedAt = Date.now();
        }

        onCompleted: res => {
            completedDuringStart = true;
            if (!allowed)
                return;

            switch (res) {
            case PamResult.Success:
                stop();
                passwd.abort();
                root.proceedAfterPrimaryAuth();
                return;
            case PamResult.Error:
                if (attemptSettled()) {
                    stop();
                    errorTries = 0;
                    startAttempt();
                    return;
                }
                scheduleErrorRetry();
                return;
            case PamResult.Failed:
            case PamResult.MaxTries:
                stop();
                tries++;
                errorTries = 0;
                root.fprintState = tries < SettingsData.maxFprintTries ? "fail" : "max";
                root.flashMsg();
                fprintStateReset.restart();
                startAttempt();
                return;
            }
        }
    }

    PamContext {
        id: u2f

        property bool available: SettingsData.lockU2fReady && (!AdminPolicy.disableCustomLockPam || u2fConfigWatcher.loaded)

        function checkAvail(): void {
            if (!available || !SettingsData.enableU2f || !root.lockSecured || root.u2fSuppressedByPrimaryPam) {
                abort();
                return;
            }

            if (SettingsData.u2fMode === "or")
                abort();
        }

        function startForSecondFactor(): void {
            if (!available || !SettingsData.enableU2f || root.u2fSuppressedByPrimaryPam) {
                root.completeUnlock();
                return;
            }
            abort();
            root.u2fPending = true;
            root.u2fPendingMode = "and";
            root.u2fState = "";
            u2fPendingTimeout.restart();
            start();
        }

        function startForAlternativeAuth(): void {
            if (!available || !SettingsData.enableU2f || root.u2fSuppressedByPrimaryPam || SettingsData.u2fMode !== "or" || root.unlockInProgress || root.authBusy || active)
                return;
            abort();
            // the field is cleared for this, so an unanswered password conversation
            // must not stay open behind it
            passwd.abort();
            root.u2fPending = true;
            root.u2fPendingMode = "or";
            root.u2fState = "";
            u2fPendingTimeout.restart();
            start();
        }

        config: {
            if (AdminPolicy.disableCustomLockPam)
                return "dankshell-u2f";
            if (root.customU2fPamActive)
                return SettingsData.lockU2fPamPath.slice(SettingsData.lockU2fPamPath.lastIndexOf("/") + 1);
            return u2fConfigWatcher.loaded ? "dankshell-u2f" : "u2f";
        }
        configDirectory: {
            if (AdminPolicy.disableCustomLockPam)
                return "/etc/pam.d";
            if (root.customU2fPamActive) {
                const idx = SettingsData.lockU2fPamPath.lastIndexOf("/");
                return idx > 0 ? SettingsData.lockU2fPamPath.slice(0, idx) : "/";
            }
            return u2fConfigWatcher.loaded ? "/etc/pam.d" : Quickshell.shellDir + "/assets/pam";
        }

        onMessageChanged: {
            if (message.toLowerCase().includes("touch"))
                root.u2fState = "waiting";
        }

        onCompleted: res => {
            if (!available || root.unlockInProgress)
                return;

            if (res === PamResult.Success) {
                root.completeUnlock();
                return;
            }

            if (res === PamResult.Error || res === PamResult.MaxTries || res === PamResult.Failed) {
                abort();

                if (root.u2fPending) {
                    if (root.u2fPendingMode === "or") {
                        root.u2fPending = false;
                        root.u2fPendingMode = "";
                        root.u2fState = root.u2fState === "waiting" ? "" : "insert";
                        u2fPendingTimeout.running = false;
                        fprint.checkAvail();
                        return;
                    }

                    if (root.u2fState === "waiting") {
                        // AND mode: device was found but auth failed → back to password
                        root.u2fPending = false;
                        root.u2fPendingMode = "";
                        root.u2fState = "";
                        fprint.checkAvail();
                    } else {
                        // AND mode: no device found → keep pending, show "Insert...", retry
                        root.u2fState = "insert";
                        u2fErrorRetry.restart();
                    }
                } else {
                    root.u2fState = "insert";
                }
            }
        }
    }

    Timer {
        id: errorRetry

        // A device wedged by a suspend mid-verify only comes back when fprintd
        // restarts, and fprintd only exits after its idle timeout with no client
        // attached, so the second retry outlasts that instead of climbing to it.
        interval: {
            if (fprint.errorTries <= 1)
                return 1500;
            if (fprint.errorTries === 2)
                return fprint.daemonIdleExitMs + 5000;
            return 60000;
        }
        onTriggered: fprint.startAttempt()
    }

    readonly property bool awaitingActivityRetry: fprint.errorTries > 0 && !fprint.retrying && !fprint.active

    function retryFprintOnActivity(): void {
        if (root.awaitingActivityRetry)
            fprint.recover();
    }

    Connections {
        target: SessionService

        function onSessionResumed() {
            fprint.recover();
        }

        function onLidOpened() {
            fprint.recover();
        }
    }

    Timer {
        id: u2fErrorRetry

        interval: 800
        onTriggered: u2f.start()
    }

    Timer {
        id: u2fPendingTimeout

        interval: 30000
        onTriggered: root.cancelU2fPending()
    }

    Timer {
        id: authRestart

        interval: 150
        onTriggered: {
            if (root.lockSecured && !root.unlockInProgress)
                root.beginAuthSession(false);
        }
    }

    Timer {
        id: eagerStart

        interval: 50
        onTriggered: {
            if (root.lockSecured && !root.unlockInProgress)
                root.beginAuthSession(false);
        }
    }

    Timer {
        id: passwdActiveTimeout

        interval: 15000
        onTriggered: {
            if (passwd.active)
                root.recoverFromAuthStall("error");
        }
    }

    Timer {
        id: unlockRequestTimeout

        interval: 8000
        onTriggered: {
            if (root.unlockInProgress)
                root.recoverFromAuthStall("error");
        }
    }

    Timer {
        id: stateReset

        interval: 4000
        onTriggered: {
            if (root.state !== "max")
                root.state = "";
        }
    }

    Timer {
        id: fprintStateReset

        interval: 4000
        onTriggered: {
            if (root.fprintState !== "max")
                root.fprintState = "";
        }
    }

    onLockSecuredChanged: {
        if (!lockSecured) {
            root.resetAuthFlows();
            return;
        }
        root.state = "";
        root.fprintState = "";
        root.u2fState = "";
        root.u2fPending = false;
        root.u2fPendingMode = "";
        root.lockMessage = "";
        root.attemptInfoMessages = [];
        root.lockoutAnnouncedThisAttempt = false;
        root.resetAuthFlows();
        root.responseSubmitted = false;
        root.responseInFlight = false;
        root.promptsSeen = 0;
        root.promptsAnswered = 0;
        root.passiveUnlockAllowed = false;
        root.autoRestartCount = 0;
        root.bufferWasEmpty = root.buffer.length === 0;
        // learn the prompt right away; this conversation may not unlock by itself
        eagerStart.restart();
        fprint.tries = 0;
        fprint.errorTries = 0;
        if (!SettingsData.lockPamExternallyManaged && !dankshellConfigWatcher.loaded && !userPamWatcher.loaded)
            ensureUserPamConfig();
        // FileView cannot watch a path that does not exist yet; re-read so a
        // dedicated service created after startup is used on the next lock.
        u2fConfigWatcher.reload();
        fprint.checkAvail();
        u2f.checkAvail();
    }

    Connections {
        target: IdleService
        enabled: root.lockSecured

        // Someone coming back wakes the outputs before they type - the same kind of
        // deliberate signal gnome gets from dismissing its shield, and it leaves a
        // window to show what pam asked for before the first character.
        function onMonitorsOffChanged(): void {
            if (!IdleService.monitorsOff)
                root.noteUnlockIntent();
        }
    }

    Connections {
        target: SettingsData

        function onEnableFprintChanged(): void {
            if (SettingsData.enableFprint)
                fprint.recover();
            else
                fprint.checkAvail();
        }

        function onLockFingerprintReadyChanged(): void {
            if (SettingsData.lockFingerprintReady)
                fprint.recover();
            else
                fprint.checkAvail();
        }

        function onEnableU2fChanged(): void {
            u2f.checkAvail();
        }

        function onLockU2fReadyChanged(): void {
            u2f.checkAvail();
        }

        function onLockPamPathChanged(): void {
            fprint.checkAvail();
            u2f.checkAvail();
        }

        function onLockPamInlineFprintChanged(): void {
            fprint.checkAvail();
        }

        function onLockPamInlineU2fChanged(): void {
            u2f.checkAvail();
        }

        function onLockPamExternallyManagedChanged(): void {
            if (AdminPolicy.disableCustomLockPam)
                return;
            root.resetAuthFlows();
            if (!SettingsData.lockPamExternallyManaged)
                root.ensureUserPamConfig();
            fprint.checkAvail();
            u2f.checkAvail();
        }

        function onLockU2fPamPathChanged(): void {
            if (AdminPolicy.disableCustomLockPam)
                return;
            u2f.abort();
            u2f.checkAvail();
        }

        function onU2fModeChanged(): void {
            if (root.lockSecured) {
                u2f.abort();
                u2fErrorRetry.running = false;
                u2fPendingTimeout.running = false;
                unlockRequestTimeout.running = false;
                root.u2fPending = false;
                root.u2fPendingMode = "";
                root.u2fState = "";
                u2f.checkAvail();
            }
        }
    }
}
