/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Justin Wong <justin.w.xd@gmail.com>
 *
 */

package hop

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bigeagle/water"
)

var net_gateway, net_nic string

type route struct {
	dest, nextHop, iface string
}

type HopClient struct {
	// config
	cfg HopClientConfig
	// interface
	iface *water.Interface
	// ip addr
	ip net.IP

	// session id
	sid [4]byte
	// session state
	state int32

	// net to interface
	toIface chan *HopPacket
	// buffer for packets from net
	recvBuf *hopPacketBuffer
	// channel to send frames to net
	toNet chan *HopPacket

	handshakeDone  chan struct{}
	handshakeError chan struct{}
	finishAck      chan byte
	// state variable to ensure serverRoute added
	srvRoute int32
	// routes need to be clean in the end
	routes []string
	// sequence number
	seq uint32
}

func NewClient(cfg HopClientConfig) error {
	var err error

	cipher, err = newHopCipher([]byte(cfg.Key))
	if err != nil {
		return err
	}

	if cfg.MTU != 0 {
		MTU = cfg.MTU
	}

	hopClient := new(HopClient)
	rand.Read(hopClient.sid[:])
	hopClient.toIface = make(chan *HopPacket, 128)
	hopClient.toNet = make(chan *HopPacket, 128)
	hopClient.recvBuf = newHopPacketBuffer(hopClient.toIface)
	hopClient.cfg = cfg
	hopClient.state = HOP_STAT_INIT
	hopClient.handshakeDone = make(chan struct{})
	hopClient.handshakeError = make(chan struct{})
	hopClient.finishAck = make(chan byte)
	hopClient.srvRoute = 0
	hopClient.routes = make([]string, 0, 1024)

	switch cfg.MorphMethod {
	case "randsize":
		log.Print("Traffic Morphing is disabled in this version")
		// m := newRandMorpher(MTU)
		// hopFrager = newHopFragmenter(m)
		// log.Print("Using RandomSize Morpher")
	default:
		log.Print("No Traffic Morphing")
	}

	go hopClient.cleanUp()

	//log.Printf("Net tun")
	iface, err := newTun("")
	if err != nil {
		log.Println(err)
		return err
	}
	hopClient.iface = iface

	net_gateway, net_nic, err = getNetGateway()
	if err != nil {
		return err
	}
	//log.Printf("Net Gateway: %s %s", net_gateway, net_nic)

	for port := cfg.HopStart; port <= cfg.HopEnd; port++ {
		server := fmt.Sprintf("%s:%d", cfg.Server, port)
		//log.Printf("handleUDP: ", server)
		go hopClient.handleUDP(server)
	}

	// wait until handshake done
wait_handshake:
	for {
		select {
		case <-hopClient.handshakeDone:
			log.Println("Handshake Success")
			break wait_handshake
		case <-hopClient.handshakeError:
			return errors.New("Handshake Fail")
		case <-time.After(3 * time.Second):
			log.Println("Handshake Timeout")
			atomic.CompareAndSwapInt32(&hopClient.state, HOP_STAT_HANDSHAKE, HOP_STAT_INIT)
		}
	}

	routeDone := make(chan bool)
	go func() {
		//log.Printf("Adding routes: ...")
		for _, dest := range cfg.Net_gateway {
			addRoute(dest, net_gateway, net_nic)
			hopClient.routes = append(hopClient.routes, dest)
		}
		if cfg.Redirect_gateway {
			routeDone <- true
		}
	}()

	// PostUp
	if cfg.Up != "" {
		args := strings.Split(cfg.Up, " ")
		var cmd *exec.Cmd
		if len(args) == 1 {
			cmd = exec.Command(args[0])
		} else {
			cmd = exec.Command(args[0], args[1:]...)
		}
		log.Print(cfg.Up)
		cmd.Run()
	}

	if cfg.Redirect_gateway {
		go func() {
			<-routeDone
			err = redirectGateway(iface.Name(), tun_peer.String())
			if err != nil {
				log.Print(err.Error())
				return
			}
		}()
	}

	hopClient.handleInterface()

	return errors.New("Not expected to exit")
}

func (clt *HopClient) handleInterface() {
	// network packet to interface
	go func() {
		for {
			hp := <-clt.toIface
			// //log.Printf("New Net packet to device")
			_, err := clt.iface.Write(hp.payload)
			// //log.Printf("n: %d, len: %d", n, len(hp.payload))
			if err != nil {
				log.Print(err.Error())
				return
			}
		}
	}()

	frame := make([]byte, IFACE_BUFSIZE)
	for {
		n, err := clt.iface.Read(frame)
		if err != nil {
			log.Print(err.Error())
			return
		}

		buf := make([]byte, n+HOP_HDR_LEN)
		copy(buf[HOP_HDR_LEN:], frame[:n])
		hp := new(HopPacket)
		hp.payload = buf[HOP_HDR_LEN:]
		hp.buf = buf
		hp.Seq = clt.Seq()
		clt.toNet <- hp
		/*
		   if hopFrager == nil {
		       // if no traffic morphing
		       // Hack to reduce memcopy

		   } else {
		       // with traffic morphing
		       packets := hopFrager.Fragmentate(clt, buf[HOP_HDR_LEN:])
		       for _, hp := range(packets) {
		           clt.toNet <- hp
		       }
		   }
		*/
	}
}

func (clt *HopClient) handleUDP(server string) {

	udpAddr, _ := net.ResolveUDPAddr("udp", server)
	udpConn, _ := net.DialUDP("udp", nil, udpAddr)

	//log.Printf(udpConn.RemoteAddr().String())

	// packet map
	pktHandle := map[byte](func(*net.UDPConn, *HopPacket)){
		HOP_FLG_HSH | HOP_FLG_ACK: clt.handleHandshakeAck,
		HOP_FLG_HSH | HOP_FLG_FIN: clt.handleHandshakeError,
		HOP_FLG_PSH:               clt.handleHeartbeat,
		HOP_FLG_PSH | HOP_FLG_ACK: clt.handleKnockAck,
		HOP_FLG_DAT:               clt.handleDataPacket,
		HOP_FLG_DAT | HOP_FLG_MFR: clt.handleDataPacket,
		HOP_FLG_FIN | HOP_FLG_ACK: clt.handleFinishAck,
		HOP_FLG_FIN:               clt.handleFinish,
	}

	go func() {
		for {
			clt.knock(udpConn)
			n := mrand.Intn(1000)
			time.Sleep(time.Duration(n) * time.Millisecond)
			clt.handeshake(udpConn)
			select {
			case <-clt.handshakeDone:
				return
			case <-time.After(5 * time.Second):
				log.Printf("Handshake timeout, retry")
			}
		}
	}()

	go func() {
		var intval time.Duration

		if clt.cfg.Heartbeat_interval <= 0 {
			intval = time.Second * 30
		} else {
			intval = time.Second * time.Duration(clt.cfg.Heartbeat_interval)
		}
		for {
			time.Sleep(intval)
			if clt.state == HOP_STAT_WORKING {
				clt.knock(udpConn)
			}
		}
	}()

	// add route through net gateway
	if clt.cfg.Redirect_gateway && (!clt.cfg.Local) {
		if atomic.CompareAndSwapInt32(&clt.srvRoute, 0, 1) {
			if udpAddr, ok := udpConn.RemoteAddr().(*net.UDPAddr); ok {
				srvIP := udpAddr.IP.To4()
				if srvIP != nil {
					srvDest := srvIP.String() + "/32"
					addRoute(srvDest, net_gateway, net_nic)
					clt.routes = append(clt.routes, srvDest)
				}
			}
		}
	}

	// forward iface frames to network
	go func() {
		for {
			hp := <-clt.toNet
			hp.setSid(clt.sid)
			// //log.Printf("New iface frame")
			// dest := waterutil.IPv4Destination(frame)
			// //log.Printf("ip dest: %v", dest)

			udpConn.Write(hp.Pack())
		}
	}()

	buf := make([]byte, IFACE_BUFSIZE)
	for {
		////log.Printf("waiting for udp packet")
		n, err := udpConn.Read(buf)
		////log.Printf("New UDP Packet, len: %d", n)
		if err != nil {
			log.Printf(err.Error())
			continue
		}

		hp, err := unpackHopPacket(buf[:n])
		if err != nil {
			//log.Printf("Error depacketing")
			continue
		}
		if handle_func, ok := pktHandle[hp.Flag]; ok {
			handle_func(udpConn, hp)
		} else {
			log.Printf("Unkown flag: %x", hp.Flag)
		}
	}
}

func (clt *HopClient) Seq() uint32 {
	return atomic.AddUint32(&clt.seq, 1)
}

func (clt *HopClient) toServer(u *net.UDPConn, flag byte, payload []byte, noise bool) {
	hp := new(HopPacket)
	hp.Flag = flag
	hp.Seq = clt.Seq()
	hp.setPayload(payload)
	if noise {
		hp.addNoise(mrand.Intn(MTU - 64 - len(payload)))
	}
	u.Write(hp.Pack())
}

// knock server port or heartbeat
func (clt *HopClient) knock(u *net.UDPConn) {
	clt.toServer(u, HOP_FLG_PSH, clt.sid[:], true)
}

// handshake with server
func (clt *HopClient) handeshake(u *net.UDPConn) {
	res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_INIT, HOP_STAT_HANDSHAKE)
	// //log.Printf("raced for handshake: %v", res)

	if res {
		// log.Print("start handeshaking")
		clt.toServer(u, HOP_FLG_HSH, clt.sid[:], true)
	}
}

// finish session
func (clt *HopClient) finishSession() {
	log.Print("Finishing Session")
	atomic.StoreInt32(&clt.state, HOP_STAT_FIN)
	hp := new(HopPacket)
	hp.Flag = HOP_FLG_FIN
	hp.setPayload(clt.sid[:])
	hp.Seq = clt.Seq()
	clt.toNet <- hp
	clt.toNet <- hp
	clt.toNet <- hp
}

// heartbeat ack
func (clt *HopClient) handleKnockAck(u *net.UDPConn, hp *HopPacket) {
	return
}

// heartbeat ack
func (clt *HopClient) handleHeartbeat(u *net.UDPConn, hp *HopPacket) {
	log.Printf("Heartbeat from server")
	clt.toServer(u, HOP_FLG_PSH|HOP_FLG_ACK, clt.sid[:], true)
}

// handle handeshake ack
func (clt *HopClient) handleHandshakeAck(u *net.UDPConn, hp *HopPacket) {
	if atomic.LoadInt32(&clt.state) == HOP_STAT_HANDSHAKE {
		proto_version := hp.payload[0]
		if proto_version != HOP_PROTO_VERSION {
			log.Printf("Incompatible protocol version!")
			os.Exit(1)
		}

		by := hp.payload[1:6]
		ipStr := fmt.Sprintf("%d.%d.%d.%d/%d", by[0], by[1], by[2], by[3], by[4])

		ip, subnet, _ := net.ParseCIDR(ipStr)
		setTunIP(clt.iface, ip, subnet)
		if clt.cfg.FixMSS {
			fixMSS(clt.iface.Name(), false)
		}
		res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING)
		if !res {
			log.Print("Client state not expected: %d", clt.state)
		}
		log.Println("Session Initialized")
		close(clt.handshakeDone)
	}

	//log.Printf("Handshake Ack to Server")
	clt.toServer(u, HOP_FLG_HSH|HOP_FLG_ACK, clt.sid[:], true)
}

// handle handshake fail
func (clt *HopClient) handleHandshakeError(u *net.UDPConn, hp *HopPacket) {
	close(clt.handshakeError)
}

// handle data packet
func (clt *HopClient) handleDataPacket(u *net.UDPConn, hp *HopPacket) {
	// //log.Printf("New HopPacket Seq: %d", packet.Seq)
	clt.recvBuf.Push(hp)
}

// handle finish ack
func (clt *HopClient) handleFinishAck(u *net.UDPConn, hp *HopPacket) {
	clt.finishAck <- byte(1)
}

// handle finish
func (clt *HopClient) handleFinish(u *net.UDPConn, hp *HopPacket) {
	log.Print("Finish")
	pid := os.Getpid()
	syscall.Kill(pid, syscall.SIGTERM)
}

func (clt *HopClient) cleanUp() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	log.Print("Cleaning Up")

	if clt.cfg.Redirect_gateway {
		delRoute("0.0.0.0/1")
		delRoute("128.0.0.0/1")
	}

	// Pre Down
	if clt.cfg.Down != "" {
		args := strings.Split(clt.cfg.Down, " ")
		var cmd *exec.Cmd
		if len(args) == 1 {
			cmd = exec.Command(args[0])
		} else {
			cmd = exec.Command(args[0], args[1:]...)
		}
		log.Print(clt.cfg.Down)
		cmd.Run()
	}

	if clt.cfg.FixMSS {
		clearMSS(clt.iface.Name(), false)
	}

	timeout := time.After(3 * time.Second)
	if clt.state != HOP_STAT_INIT {
		clt.finishSession()
	}

	select {
	case <-clt.finishAck:
		log.Print("Finish Acknowledged")
	case <-timeout:
		log.Print("Timeout, give up")
	}

	for _, dest := range clt.routes {
		delRoute(dest)
	}

	os.Exit(0)
}
