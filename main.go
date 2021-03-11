package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jessevdk/go-flags"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"path"
	"sync"
	"github.com/vishvananda/netlink"
)

const VERSION = "0.0.1"

var opts struct {
	Version bool `short:"V" long:"version" description:"Print the application version number and exit"`
	Verbose bool `short:"v" long:"verbose" env:"GENEVE_VERBOSE" description:"Enable DEBUG logging"`

	// Listener settings
	Port int `short:"p" long:"port" env:"GENEVE_PORT" description:"UDP port to accept GENEVE packets on" default:"6081"`
	Listen string `short:"l" long:"listen" env:"GENEVE_LISTEN" description:"Hostname to listen on" default:"0.0.0.0"`

	// Tunnel settings
	TunnelName string `short:"t" long:"tunnel-name" env:"GENEVE_TUNNEL_NAME" description:"Set the linux TUN name (optional)"`
	MTU int `short:"m" long:"mtu" env:"GENEVE_MTU" description:"MTU size of the encapsulated packets"`

}

type glbOpts struct {
	ENIId string
	AttachmentId string
	FlowCookie string
}

const (
	AWS_GENEVE_OPTCLASS = 0x0108
	AWS_GENEVE_OPT_ENI_ID = 0x1
	AWS_GENEVE_OPT_ATTACHMENT_ID = 0x2
	AWS_GENEVE_OPT_FLOW_COOKIE = 0x3
)

func setupGeneveListener(host string, port int) *net.UDPConn {
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", opts.Listen, opts.Port))
	if err != nil {
		log.Fatalf("Unable to resolve address: %s\n", err)
	}

	listener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Unable to listen to UDP socket: %s\n", err)
	}
	log.Infof("UDP server up and listening on port %s:%d\n", opts.Listen, opts.Port)

	return listener
}

func setupTunDevice(name string) *water.Interface {
	config := water.Config{
		DeviceType: water.TUN,
	}
	if name != "" {
		config.Name = name
	}

	ifce, err := water.New(config)
	if err != nil {
		log.Fatalf("Unable to create tunnel device: %s\n", err)
	}
	log.Infof("Created tunnel device: %s\n", ifce.Name())

	nl, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		log.Fatalf("Unable to find netlink device: %s\n", err)
	}

	err = netlink.LinkSetUp(nl)
	if err != nil {
		log.Fatalf("Unable to set link up: %s\n", err)
	}

	return ifce
}

// Handle an incoming UDP GENEVE connection
// Decapsulate the nested IPv4 packet and pass it to the tunnel
func handleGeneve(conn *net.UDPConn, tunnel *water.Interface) {
	buffer := make([]byte, 1024)

	_, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		log.Fatalf("Unable to read UDP packet: %s\n", err)
	}

	log.WithField("addr", addr).Debug("RX packet from UDP client")

	packet := gopacket.NewPacket(buffer, layers.LayerTypeGeneve, gopacket.Default)
	log.WithFields(log.Fields{
		"packet": packet,
		"client_addr": addr,
	}).Trace("Packet decoded")

	// Guard against AWS suddenly supporting new GENEVE-encapsulated formats we don't understand
	// (we aren't trying to become a generic GENEVE tunnel here)
	if packet.Layers()[1].LayerType() != layers.LayerTypeIPv4 {
		log.WithFields(log.Fields{
			"layer_type": packet.Layers()[1].LayerType(),
		}).Errorf("Received a GENEVE packet from the GLB that doesn't contain an IPv4 packet! Unable to proceed.")
		return
	}

	// Pass the packet to the tunnel device
	_, err = tunnel.Write(packet.Layers()[1].LayerPayload())
	if err != nil {
		log.Fatalf("Unable to write packet to tunnel device: %s\n", err)
	}

}

// Handle an incoming packet on the TUN device
// Build a GENEVE header from the incoming packet and pass it to the UDP port
func handleTunnel(tunnel *water.Interface, conn *net.UDPConn) {
	var frame ethernet.Frame

	frame.Resize(1500)
	n, err := tunnel.Read(frame)
	if err != nil {
		log.Fatalf("Unable to read frame from tunnel: %s\n", err)
	}
	frame = frame[:n]
	log.WithField("frame", frame).Trace("rx frame")

	if frame.Ethertype() == ethernet.IPv4 {
		buildGenevePacket(frame, &glbOpts{ENIId: "", AttachmentId: "", FlowCookie: ""})
	} else {
		log.Tracef("Unable to build GENEVE packet from ethertype %s", frame.Ethertype())
	}


}


// Build a GENEVE packet from a IPv4 packet
func buildGenevePacket(packet []byte, pktOpts *glbOpts) []byte {
	geneveHeader := &AWSGeneve{
		Geneve: layers.Geneve{
			Version: 1,
			// We contain only an IPv4 packet per the AWS GLB specification
			Protocol: layers.EthernetTypeIPv4,
			// Ce n'est pas un paquet de gestion
			OAMPacket: false,
			// AWS says that you must pass back the GeneveOptions they send, but they aren't marked as critical options
			// ...which means you could technically drop them (according to the GENEVE spec) and nothing bad would happen
			// but we'll assume AWS just doesn't know what they're doing and pass them back the same options
			CriticalOption: false,
			// AWS also says VNI=0 is constant, we'll see how long that lasts for...
			VNI: 0,
			// These are the opts that we received from the incoming GENEVE packet
			Options: []*layers.GeneveOption{
				// GLB ENI ID
				{
					Class: AWS_GENEVE_OPTCLASS,
					Type: AWS_GENEVE_OPT_ENI_ID,
					Data: []byte{},
				},
				// Attachment ID
				{
					Class:  AWS_GENEVE_OPTCLASS,
					Type:   AWS_GENEVE_OPT_ATTACHMENT_ID,
					Data:   []byte{},
				},
				// Flow Cookie
				{
					Class: AWS_GENEVE_OPTCLASS,
					Type: AWS_GENEVE_OPT_FLOW_COOKIE,
					Data: []byte{},
				},
			},
		},
	}

	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options,
		geneveHeader,
		gopacket.Payload(packet),
	)
	if err != nil {
		log.Fatalf("Unable to serialize packet into GENEVE format: %s\n", err)
	}

	return buffer.Bytes()
}

func main() {
	// Parse arguments
	_, err := flags.Parse(&opts)
	if err != nil {
		typ := err.(*flags.Error).Type
		if typ == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if opts.Version {
		exe, _ := os.Executable()
		fmt.Println(path.Base(exe), "Version", VERSION)
		os.Exit(2)
	}

	// Logging goodness
	if opts.Verbose {
		log.SetLevel(log.TraceLevel)
	}
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		PadLevelText: true,
		DisableLevelTruncation: true,
	})

	// Setup the GENEVE listener
	log.WithFields(log.Fields{"host": opts.Listen, "port": opts.Port}).Debug("Creating GENEVE listener")
	listener := setupGeneveListener(opts.Listen, opts.Port)
	defer listener.Close()

	// Setup the TUN device
	log.WithFields(log.Fields{"tun_name": opts.TunnelName}).Debug("Creating TUN interface")
	tun := setupTunDevice(opts.TunnelName)

	// Wait
	var wg sync.WaitGroup
	wg.Add(2)

	// goroutine for listening for GENEVE connections
	go func() {
		log.Trace("Ready to accept GENEVE connections")
		for {
			handleGeneve(listener, tun)
		}
	}()

	// goroutine for listening for TUN connections
	go func() {
		log.Trace("Ready to accept TUN connections")
		for {
			handleTunnel(tun, listener)
		}
	}()

	// Wait forever
	wg.Wait()

}