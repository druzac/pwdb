var db = undefined;
var sorted_recs = undefined;

function dbLookup(uuid) {
    if (db === undefined)
        return null;
    return db.records[uuid];
}

function updateSelection(selectEl) {
    var n_children = selectEl.children.length;
    for (var i = n_children - 1; i >= 0; i--) {
        selectEl.removeChild(selectEl.children[i]);
    }
    for (var i = 0; i < sorted_recs.length; i++) {
        var opt = document.createElement("OPTION");
        opt.value = sorted_recs[i].uuid;
        opt.innerText = sorted_recs[i].title;
        selectEl.appendChild(opt);
    }
}

function contextMenuTest(info) {
    console.log("menu item id: " + info.menuItemId);
    console.log("sending message");
    for (var i = 0; i < sorted_recs.length; i++) {
        if (sorted_recs[i].uuid === info.menuItemId) {
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                chrome.tabs.sendMessage(tabs[0].id, {greeting: "hello", payload: sorted_recs[i].password});
            });
            break;
        }
    }
}

function updateContextMenus() {
    chrome.contextMenus.removeAll(function() {
        for (var i = 0; i < sorted_recs.length; i++) {
            chrome.contextMenus.create({"title": sorted_recs[i].title,
                                        "contexts": ["editable"],
                                        "id": sorted_recs[i].uuid,
                                        "onclick": contextMenuTest});
        }
    });
}

function rewriteStuff(e) {
    var par = document.getElementById("test_par");
    var pw_field = document.getElementById("pw");
    pwdbGetDump(pw_field.value, par);
};

function pwdbGetDump(pw, item) {
    var x = new XMLHttpRequest();
    x.onreadystatechange = function() {
        if (x.readyState == XMLHttpRequest.DONE) {
            console.log("ready state: " + x.readyState);
            var data = JSON.parse(x.responseText);
            if (data.err == 0) {
                // TODO display this information on page
                console.log("access granted");
                db = data.res;
                sorted_recs = []
                var records = db.records;

                for (var key in records) {
                    // skip loop if the property is from prototype
                    if (!records.hasOwnProperty(key)) continue;

                    var rec = records[key];
                    console.log("rec is: " + JSON.stringify(rec));
                    rec.uuid = key
                    sorted_recs.push(rec);
                }
                sorted_recs.sort(function (rec1, rec2) {
                    return (rec1.title < rec2.title ? -1 :
                            rec1.title > rec2.title ? 1 : 0);
                });
                updateSelection(document.getElementById("entries"));
                updateContextMenus();
            } else {
                console.log("access denied: " + JSON.stringify(data));
            }
        }
    };
    x.open("GET", "http://127.0.0.1:3000/dump?password=" + pw, true);
    x.send();
}

function showEntry(e) {
    var entriesEl = document.getElementById('entries');
    var uuid = entriesEl.options[entriesEl.selectedIndex].value;
    var entry = dbLookup(uuid);
    if (entry !== null) {
        document.getElementById('entry_title').value = entry.title;
        document.getElementById('entry_password').value = entry.password;
        document.getElementById('entry_uuid').value = entry.uuid;
        hidePassword();
    } else {
        console.log("couldn't get entry");
    }
}

function toggleShowEntryPassword(e) {
    var entryPassEl = document.getElementById('entry_password');
    entryPassEl.type = entryPassEl.type === "password" ?
        "text" : "password";
}

function hidePassword() {
    var entryPassEl = document.getElementById('entry_password');
    entryPassEl.type = "password";
}

document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('init').addEventListener('click', rewriteStuff);
    document.getElementById('edit').addEventListener('click', showEntry);
    document.getElementById('toggle_password').addEventListener('click', toggleShowEntryPassword);
});
