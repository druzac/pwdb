// url encoding?
// function pwdbGetDump(pw) {
//     var x = new XMLHttpRequest();
//     x.onreadystatechange = function() {
//         // console.log("ready state: " + x.readyState);
//         var data = JSON.parse(x.responseText);
//         console.log("data is: " + JSON.stringify(data));
//     }
//     x.open("GET", "http://127.0.0.1:3000/dump?password=" + pw, true);
//     x.send();
// }

// function myFunction(e) {
//     // console.log("hello");
//     document.getElementById("demo").innerHTML = "Hello World";
//     document.getElementById("status").textContent = "Hello World";
//     // console.log("hmmm this is interesting...");
// }

function gotoLoginPage(e) {
    chrome.tabs.create({url: "pwdb.html"});
};

document.addEventListener('DOMContentLoaded', function () {
  document.querySelector('button').addEventListener('click', gotoLoginPage);
});

// document.addEventListener('DOMContentLoaded', function () {
//   document.querySelector('button').addEventListener('click', myFunction);
// });
