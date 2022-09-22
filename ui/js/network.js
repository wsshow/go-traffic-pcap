//Network.js
var WebSocket = WebSocket || window.WebSocket || window.MozWebSocket;

var Network = (function () {
    var instance = null;

    function getNetworkInstance() {
        var networkInstance = {
            socket: null,
            isInit: false,
            initNetwork: function () {
                console.log("Network initSocket...");
                this.host = "ws://127.0.0.1:9666/ws";
                this.socket = new WebSocket(this.host);
                var self = this;
                this.socket.onopen = function (evt) {
                    console.log("Network onopen.");
                    self.isInit = true;
                };

                this.socket.onmessage = function (evt) {
                    var data = evt.data;
                    console.log("Network onmessage:", data);
                };

                this.socket.onerror = function (evt) {
                    console.log("Network onerror:", evt);
                };

                this.socket.onclose = function (evt) {
                    console.log("Network onclose.");
                    this.isInit = false;
                };
            },
            send: function (data) {
                if (!this.isInit) {
                    console.log("Network is not inited...");
                } else if (this.socket.readyState == WebSocket.OPEN) {
                    console.log("Network send:" + data);
                    this.socket.send(data);
                } else {
                    console.log("Network WebSocket readState:" + this.socket.readyState);
                }
            },
            close: function () {
                if (this.socket) {
                    console.log("Network close.");
                    this.socket.close();
                    this.socket = null;
                }
            },
        };
        return networkInstance;
    }

    return {
        getInstance: function () {
            if (instance === null) {
                instance = getNetworkInstance();
            }
            return instance;
        },
    };
})();
