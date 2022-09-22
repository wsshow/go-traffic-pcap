package router

import (
	"go-traffic-pcap/controller"

	"github.com/gin-gonic/gin"
)

func Init(r *gin.Engine) {
	r.GET("/ws", controller.WsHandler())
	r.GET("/devicesName", controller.GetDevicesName())
	r.POST("/openOffline", controller.OpenOffline())
	r.POST("/pcapVersion", controller.GetPCapVersion())
	r.POST("/startPcap", controller.StartPcap())
	r.POST("/stopPcap", controller.StopPcap())
}
