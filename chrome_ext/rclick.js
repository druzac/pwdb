// content script
// responsible for modifying the dom element

chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
      console.log(sender.tab ?
                  "from a content script:" + sender.tab.url :
                  "from the extension");
      if (request.greeting == "hello") {
          console.log(document.activeElement);
          var currEl = document.activeElement;
          currEl.value += request.payload;
      }
  });
