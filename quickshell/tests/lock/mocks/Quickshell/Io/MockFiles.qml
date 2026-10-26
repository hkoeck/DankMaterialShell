pragma Singleton
import QtQuick

QtObject {
    property var missing: []
    // path -> file contents, for the views whose text the shell reads
    property var contents: ({})
}
