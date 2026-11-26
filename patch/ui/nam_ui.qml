import QtQuick 2.2

// NAM pedals: the parameters under their real names (the stock tiles still say DRIVE / LEVEL / TONE: the engine knobs
// are a Glorious Drive clone's), and the model number and name from one value. The stock Drive readout formats its text when the value changes,
// with whatever name the hook had written by then, and keeps it until the next change, so it can show the number of
// one model and the name of another. This page derives both from the live value (the model list is written by the
// hook as /tmp/nam_models.qml) and, while open, re-assigns the value whenever the stock text disagrees so that the
// readouts on the left refresh as well.
Column {
	id: root
	width: 720
	property var blockPage

	property string pedal: blockPage && blockPage.moduleTypeProp ? blockPage.moduleTypeProp.translator.string : ""
	property var drive: pedal !== "" ? Evil.getProperty("/Engine/Patch/" + pedal + "/Drive") : null
	property double stamp: new Date().getTime()
	property var names: modelList.item ? modelList.item.names : []
	property real raw: drive && drive.translator ? drive.translator.unnormalized : -1
	property int idx: names.length > 0 ? Math.max(0, Math.min(names.length - 1, Math.round(raw) - 1)) : -1
	property string stock: drive && drive.translator ? drive.translator.string : ""
	property var level: pedal !== "" ? Evil.getProperty("/Engine/Patch/" + pedal + "/Level") : null
	property var tone: pedal !== "" ? Evil.getProperty("/Engine/Patch/" + pedal + "/Tone") : null
	property var gain: pedal !== "" ? Evil.getProperty("/Engine/Patch/" + pedal + "/Gain") : null
	property string inputText: level && level.translator ? level.translator.string : ""
	property string outputText: tone && tone.translator ? tone.translator.string : ""
	property string calibText: gain && gain.translator ? (gain.translator.index === 1 ? "ON" : "OFF") : ""
	property string expected: idx >= 0 ? Math.round(raw) + " " + names[idx] : ""

	// NAM quality of this pedal (namespace quality in nam_hook.cpp). This Qt has no XMLHttpRequest: a button loads
	// /tmp/nam_mode/<pedal, spaces as _>-<mode>.png and the hook sees the file being opened; the hook writes every
	// pedal's mode to /tmp/nam_mode_state.qml. A pedal the hook doesn't know yet reads as AUTO.
	readonly property var qualityFiles: ["auto", "lite", "full"]
	readonly property var qualityNames: ["AUTO", "LITE", "FULL"]
	readonly property var qualityNotes: ["Full when it fits", "fast rig changes", "1 NAM, Tails off"]
	property int quality: modeState.item && pedal !== "" && modeState.item.modes[pedal] !== undefined ? modeState.item.modes[pedal] : 0
	property string trigger: ""
	property double modeStamp: new Date().getTime()
	Loader { id: modeState; source: "file:///tmp/nam_mode_state.qml?" + root.modeStamp }
	Image { width: 1; height: 1; opacity: 0; cache: false; source: root.trigger }
	Timer { id: modeRefresh; interval: 400; onTriggered: root.modeStamp = new Date().getTime() }
	function chooseQuality(q) {
		trigger = "file:///tmp/nam_mode/" + pedal.replace(/ /g, "_") + "-" + qualityFiles[q] + ".png?" + new Date().getTime()
		modeRefresh.restart()
	}

	Loader { id: modelList; source: "file:///tmp/nam_models.qml?" + root.stamp }

	onRawChanged: fixTimer.restart()
	Timer {
		id: fixTimer
		interval: 40; repeat: true; running: true
		onTriggered: {
			if (root.drive && root.drive.translator && root.expected !== "" && root.stock !== root.expected)
				root.drive.translator.unnormalized = root.raw
		}
	}

	Rectangle {
		width: 720; height: 110; color: "#1b2a18"; border.color: "#44F511"; border.width: 2
		Text { x: 20; y: 8; color: "#9fd99a"; font.pixelSize: 26; text: "MODEL" }
		Text {
			x: 20; y: 38; width: 680; elide: Text.ElideRight; color: "white"; font.pixelSize: 44
			text: root.idx >= 0 ? (root.idx + 1) + "  " + root.names[root.idx] : "..."
		}
	}

	Item { width: 720; height: 2 }
	Row {
		spacing: 12
		Repeater {
			model: [["INPUT", root.inputText], ["OUTPUT", root.outputText], ["CALIBRATION", root.calibText]]
			Rectangle {
				width: 232; height: 90; color: "#2b2c2e"; border.width: 2; border.color: "#555"
				Text { x: 14; y: 8; color: "#9fd99a"; font.pixelSize: 24; text: modelData[0] }
				Text { x: 14; y: 40; width: 204; elide: Text.ElideRight; color: "white"; font.pixelSize: 38; text: modelData[1] }
			}
		}
	}

	Item { width: 720; height: 12 }
	Row {
		spacing: 12
		Repeater {
			model: 3
			Rectangle {
				width: 232; height: 80; radius: 4
				color: root.quality === index ? "#2f6b27" : "#2b2c2e"
				border.width: 2; border.color: root.quality === index ? "#44F511" : "#555"
				Text { x: 14; y: 8; color: "white"; font.pixelSize: 30; text: root.qualityNames[index] }
				Text { x: 14; y: 46; width: 204; elide: Text.ElideRight; color: "#9fd99a"; font.pixelSize: 20; text: root.qualityNotes[index] }
				MouseArea { anchors.fill: parent; onClicked: root.chooseQuality(index) }
			}
		}
	}
}
