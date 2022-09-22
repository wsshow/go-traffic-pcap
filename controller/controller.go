package controller

import (
	"encoding/json"
	"go-traffic-pcap/core"
	"go-traffic-pcap/global"
	"go-traffic-pcap/storage"
	"go-traffic-pcap/utils"
	"log"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	resp utils.Response
)

func GetPCapVersion() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, resp.Success(core.Get().GetPcapVersion()))
	}
}

func GetDevicesName() gin.HandlerFunc {
	return func(c *gin.Context) {
		infos, err := core.Get().GetDevsInfo()
		if err != nil {
			c.JSON(http.StatusOK, resp.Failure().WithDesc("获取网卡设备信息失败"))
			return
		}
		c.JSON(http.StatusOK, resp.Success(infos))
	}
}

func StartPcap() gin.HandlerFunc {
	return func(c *gin.Context) {
		var conf storage.PcapConfig
		if err := c.ShouldBindJSON(&conf); err != nil {
			c.JSON(http.StatusOK, resp.Failure().WithDesc(err.Error()))
			return
		}
		lpcap := core.Get()
		if lpcap.IsPcapRunning() {
			c.JSON(http.StatusOK, resp.Failure().WithDesc("正在抓包，请勿重复运行"))
			return
		}
		if err := lpcap.StartPcap(conf); err != nil {
			c.JSON(http.StatusOK, resp.Failure().WithDesc(err.Error()))
			return
		} else {
			c.JSON(http.StatusOK, resp.Success(nil))
		}
	}
}

func StopPcap() gin.HandlerFunc {
	return func(c *gin.Context) {
		if core.Get().IsPcapRunning() {
			core.Get().StopPcap()
			c.JSON(http.StatusOK, resp.Success(core.Get().GetCurPcapPath()))
			return
		}
		c.JSON(http.StatusOK, resp.Failure().WithDesc("尚未开始抓包"))
	}
}

func OpenOffline() gin.HandlerFunc {
	return func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusOK, resp.Failure().WithDesc(err.Error()))
			return
		}
		const tmpDir = "./tmp"
		if !utils.IsPathExist(tmpDir) {
			err = utils.CreatDir(tmpDir)
			if err != nil {
				log.Println("OpenOffline CreatDir error:", err)
				return
			}
		}
		pcapPath := filepath.Join(tmpDir, file.Filename)
		err = c.SaveUploadedFile(file, pcapPath)
		if err != nil {
			c.JSON(http.StatusOK, resp.Failure().WithDesc(err.Error()))
			return
		}
		pis, err := core.Get().OpenOffline(pcapPath)
		if err != nil {
			c.JSON(http.StatusOK, resp.Failure().WithDesc(err.Error()))
			return
		}
		c.JSON(http.StatusOK, resp.Success(pis))
	}
}

func WsHandler() gin.HandlerFunc {
	var upGrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	return func(c *gin.Context) {
		ws, err := upGrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		go func() {
			for msg := range global.ChPacketInfo {
				bs, err := json.Marshal(msg)
				if err != nil {
					log.Println(err)
					return
				}
				err = ws.WriteMessage(1, bs)
				if err != nil {
					log.Println(err)
					return
				}
			}
		}()
		type ResFromClient struct {
			Code int                `json:"code,omitempty"`
			Conf storage.PcapConfig `json:"conf,omitempty"`
		}
		var res ResFromClient
		for {
			err := ws.ReadJSON(&res)
			if err != nil {
				log.Println(err)
				return
			}
			if res.Code == 1 {
				if core.Get().IsPcapRunning() {
					core.Get().StopPcap()
				}
				continue
			}
			if res.Code == 2 {
				lpcap := core.Get()
				if lpcap.IsPcapRunning() {
					log.Println("正在抓包，请勿重复运行")
					continue
				}
				if err := lpcap.StartPcap(res.Conf); err != nil {
					log.Println(err)
				} else {
					log.Println("开始抓包")
				}
				continue
			}
		}
	}
}
