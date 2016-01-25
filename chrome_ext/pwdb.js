// take the password from the field
// make an http request to pwdbsrv
// dump all logins to the webpage somehow

var db = undefined;

function updateSelection(selectEl) {
    var n_children = selectEl.children.length;
    for (var i = n_children - 1; i >= 0; i--) {
        selectEl.removeChild(selectEl.children[i]);
    }
    for (var i = 0; i < db.length; i++) {
        var opt = document.createElement("OPTION");
        opt.value = db[i].uuid;
        opt.innerText = db[i].title;
        selectEl.appendChild(opt);
    }
};

function contextMenuTest(info) {
    console.log("menu item id: " + info.menuItemId);
    console.log("sending message");
    for (var i = 0; i < db.length; i++) {
        if (db[i].uuid === info.menuItemId) {
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                chrome.tabs.sendMessage(tabs[0].id, {greeting: "hello", payload: db[i].password});
            });
            break;
        }
    }
};

function updateContextMenus() {
    chrome.contextMenus.removeAll(function() {
        for (var i = 0; i < db.length; i++) {
            chrome.contextMenus.create({"title": db[i].title,
                                        "contexts": ["editable"],
                                        "id": db[i].uuid,
                                        "onclick": contextMenuTest});
        }
    });
};

function rewriteStuff(e) {
    var par = document.getElementById("test_par");
    var pw_field = document.getElementById("pw");
    // par.textContent = "you entered: " + pw_field.value;
    pwdbGetDump(pw_field.value, par);
    // chrome.tabs.create({url: "login.html"});
};

// copy pasted from popup.js
function pwdbGetDump(pw, item) {
    var x = new XMLHttpRequest();
    x.onreadystatechange = function() {
        if (x.readyState == XMLHttpRequest.DONE) {
            console.log("ready state: " + x.readyState);
            var data = JSON.parse(x.responseText);
            if (data.err == 0) {
                console.log("access granted");
                db = data.res;
                updateSelection(document.getElementById("entries"));
                updateContextMenus();
                // var entries = data.res;
                // var entriesEl = document.getElementById("entries");
                // for (var i = 0; i < entries.length; i++) {
                //     var opt = document.createElement("OPTION");
                //     opt.value = entries[i].uuid;
                //     opt.innerText = entries[i].title;
                //     entriesEl.appendChild(opt);
                // }
                // db = data.res;
            } else {
                console.log("access denied");
            }
            // this is inserting the content into the web page
            // item.textContent = JSON.stringify(data);
        }
        // console.log("data is: " + JSON.stringify(data));
    };
    x.open("GET", "http://127.0.0.1:3000/dump?password=" + pw, true);
    x.send();
}

document.addEventListener('DOMContentLoaded', function () {
  document.querySelector('button').addEventListener('click', rewriteStuff);
});

