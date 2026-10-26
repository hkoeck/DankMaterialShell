import QtQuick

Item {
    property var command
    property bool running: false
    property var stdout: null
    signal exited(int exitCode)

    Component.onCompleted: MockProcesses.register(this)
    Component.onDestruction: MockProcesses.forget(this)

    // Tests answer a process by hand: whatever the shell would have read on
    // stdout, followed by the exit code.
    function finish(output, exitCode) {
        running = false;
        if (stdout && output !== undefined)
            stdout.deliver(output);
        exited(exitCode);
    }
}
