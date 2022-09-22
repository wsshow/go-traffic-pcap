function doNotify(title, options = {}, events = {}) {
  const notification = new Notification(title, options);
  for (let event in events) {
    notification[event] = events[event];
  }
}

function notify(title, options = {}, events = {}) {
//   console.log(title, options, events);
  if (!("Notification" in window)) {
    return console.error("This browser does not support desktop notification");
  } else if (Notification.permission === "granted") {
    doNotify(title, options, events);
  } else if (Notification.permission !== "denied") {
    Notification.requestPermission().then(function (permission) {
      if (permission === "granted") {
        doNotify(title, options, events);
      }
    });
  }
}
