import QtQuick

Item {
    property string text: ""
    signal streamFinished

    // Tests push a process's output through this; the real collector emits
    // streamFinished once the stream closes.
    function deliver(output) {
        text = output;
        streamFinished();
    }
}
