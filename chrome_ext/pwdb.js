var db = undefined;
var sorted_recs = undefined;

function getEl(id) { return document.getElementById(id); }

function logJson(obj) { console.log(JSON.stringify(obj)); }

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

function refreshState(dbArg) {
    db = dbArg;
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
    var pw = document.getElementById("pw").value;
    pwdb.dump(pw, refreshState, logJson);
};

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

function deleteEntry(e) {
    var pw = getEl("pw").value;
    var uuid = getEl("entry_uuid").value;
    console.log("delete function got uuid: " + uuid);
    pwdb.remove_record(
        pw, uuid,
        refreshState,
        logJson
    );
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

function addEntry(e) {
    var db_pw = getEl("pw").value;
    var title = getEl("entry_title").value;
    var pw = getEl("entry_password").value;
    console.log("args to add_record: " + db_pw + ", " + title + ", " + pw);
    pwdb.add_record(
        db_pw, title, pw,
        refreshState,
        logJson
    );
}

function PwdbClient(addr, port) {
    this.addr = addr;
    this.port = port;
    this.call = function(method, url, happyCont, errCont) {
        var x = new XMLHttpRequest();
        x.onreadystatechange = function() {
            if (x.readyState == XMLHttpRequest.DONE) {
                var data = JSON.parse(x.responseText);
                if (data.err == 0) {
                    console.log("calling happy continuation");
                    happyCont(data.res);
                } else {
                    console.log("calling error continuation");
                    errCont(data);
                }
            }
        };
        x.open(method, url, true);
        x.send();
    };
    this.dump = function(pw, happyCont, errCont) {
        this.call(
            "GET",
            "http://" + this.addr + ":" + this.port + "/dump?password=" + pw,
            happyCont,
            errCont
        );
    };
    this.add_record = function(db_pw, title, rec_pw, hcont, econt) {
        this.call(
            "POST",
            "http://" + this.addr + ":" + this.port +
                "/add_record?db_password=" + db_pw + "&title=" + title +
                "&rec_password=" + rec_pw,
            hcont,
            econt
        );
    };
    this.remove_record = function(pw, uuid, hcont, econt) {
        this.call(
            "DELETE",
            "http://" + this.addr + ":" + this.port +
                "/remove_record?password=" + pw +
                "&uuid=" + uuid,
            hcont,
            econt
        );
    };
}

var pwdb = new PwdbClient("localhost", 3000);

document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('init').addEventListener('click', rewriteStuff);
    document.getElementById('edit').addEventListener('click', showEntry);
    document.getElementById('toggle_password').addEventListener(
        'click', toggleShowEntryPassword
    );
    getEl("add").addEventListener('click', addEntry);
    getEl("delete").addEventListener('click', deleteEntry);
});
