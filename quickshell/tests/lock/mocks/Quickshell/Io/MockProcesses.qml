pragma Singleton
import QtQuick

QtObject {
    property var all: []

    function register(process) {
        all = all.concat([process]);
    }

    function forget(process) {
        all = all.filter(p => p !== process);
    }

    // Answers the newest running process whose command contains every fragment.
    // Returns false when no such process is waiting.
    function answer(fragments, output, exitCode) {
        for (let i = all.length - 1; i >= 0; i--) {
            const p = all[i];
            if (!p.running || !p.command)
                continue;
            const line = p.command.join(" ");
            if (fragments.every(f => line.includes(f))) {
                p.finish(output, exitCode);
                return true;
            }
        }
        return false;
    }
}
