package main

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/vmihailenco/msgpack"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

type FileContentType struct {
	FileName  string
	Content   []byte
	Len       int
	Md5       string
	EncodeMd5 string
}
type DumpPacketType struct {
	CrashGuid string
	Files     []FileContentType
}

var HttpUrlReceiverCrashPath = "/receiverCrash"

var HttpUrl *string = flag.String("HttpUrl", "http://localhost:3333", "")

// Client 相关参数

var AppName *string
var CrashGUID *string
var DebugSymbols *string
var ExePath string
var CrashPath string

// Server 相关参数
var CrashBasePath *string
var DumpAnlyisePath *string
var SymbolPath *string

var HttpPort = flag.Int("HttpPort", 3333, "port for http listen")

var AnalyiseChan chan string
var ExitChan chan os.Signal

func main() {
	if len(os.Args) < 2 {
		return
	}
	if strings.ToLower(os.Args[1]) == "server" {
		Server()
	} else {
		Client()
	}
}

func Client() {
	AppName = flag.String("AppName", "AppName", "")
	CrashGUID = flag.String("CrashGUID", "CrashGUID", "")
	DebugSymbols = flag.String("DebugSymbols", "DebugSymbols", "")
	flag.CommandLine.Parse(os.Args[3:])
	ExePath = os.Args[1]
	CrashPath = os.Args[2]

	pack, err := PackCrashDir(CrashPath, *CrashGUID)
	if err != nil {
		return
	}
	reader := bytes.NewBuffer(pack)
	len := reader.Len()
	if rsp, err := http.Post(*HttpUrl+HttpUrlReceiverCrashPath, "application/octet-stream", reader); err != nil {
		fmt.Printf("post %s", err.Error())
	} else {
		var buff = make([]byte, 400)
		rsp.Body.Read(buff)
		rsp.Body.Close()
		fmt.Printf("rsp %d,%s", len, string(buff))
	}
}
func isDirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
func Server() {
	CrashBasePath = flag.String("CrashBasePath", "./Crash", "crash store directory")
	DumpAnlyisePath = flag.String("DumpAnlyisePath", "C:\\Users\\xuw\\Documents\\Unreal Projects\\MyTestProject\\Binaries\\Win64\\DumpAnlyise-Win64-Development.exe", "crash anlyise execute path")
	SymbolPath = flag.String("SymbolPath", "D:\\WinDbg", "symbol&execute path")

	flag.CommandLine.Parse(os.Args[2:])

	absPath, _err := filepath.Abs(*CrashBasePath)
	if _err != nil || !isDirExists(absPath) {
		log.Fatalf("%s not exists\n", absPath)
	}

	http.HandleFunc(HttpUrlReceiverCrashPath, func(writer http.ResponseWriter, request *http.Request) {
		if strings.ToUpper(request.Method) != "POST" {
			writer.WriteHeader(405)
			return
		}
		var buff = make([]byte, 0)
		totalLen := 0
		for true {
			var tmp = make([]byte, 2048)
			recvLen, _ := request.Body.Read(tmp)
			if recvLen > 0 {
				buff = append(buff, tmp[:recvLen]...)
				totalLen = totalLen + recvLen
			} else {
				break
			}
		}
		packet := &DumpPacketType{}
		err := msgpack.Unmarshal(buff, packet)
		if err != nil {
			fmt.Printf("msgpack.Unmarshal %d,%d,%s", request.ContentLength, totalLen, err.Error())
			return
		}
		log.Printf("Recv %s\n", packet.CrashGuid)
		UnPackCrash(packet)
		io.WriteString(writer, "OK")
	})
	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", *HttpPort))
	if err != nil {
		log.Fatalf("listen err %s", err.Error())
	}
	go func() {
		fmt.Printf("Begin Listen :%d\n", *HttpPort)
		if err := http.Serve(listener, nil); err != nil {
			log.Fatalf("http server err %s", err.Error())
		}
	}()
	AnalyiseChan = make(chan string, 1024)
	ExitChan = make(chan os.Signal)
	signal.Notify(ExitChan, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	select {
	case <-ExitChan:
		return
	case Path := <-AnalyiseChan:
		AnlyiseMiniDump(Path)
	}
}

func PackCrashDir(CrashPath string, CrashGUID string) ([]byte, error) {
	packet := &DumpPacketType{}
	packet.CrashGuid = CrashGUID
	packet.Files = make([]FileContentType, 0)
	filepath.WalkDir(CrashPath, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		File, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(File)
		w.Close()
		Md5 := md5.Sum(File)
		EncodeMd5 := md5.Sum(b.Bytes())

		packet.Files = append(packet.Files, FileContentType{
			FileName:  d.Name(),
			Content:   b.Bytes(),
			Len:       len(File),
			Md5:       hex.EncodeToString(Md5[:]),
			EncodeMd5: hex.EncodeToString(EncodeMd5[:]),
		})
		fmt.Printf("FileName %s,%s,%s,%d,%d\n", d.Name(), hex.EncodeToString(Md5[:]), hex.EncodeToString(EncodeMd5[:]), b.Len(), len(File))
		return nil
	})
	return msgpack.Marshal(packet)
}
func UnPackCrash(Packet *DumpPacketType) {
	var Path = *CrashBasePath + "/" + Packet.CrashGuid
	err := os.Mkdir(Path, os.ModePerm)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}
	for _, File := range Packet.Files {
		r, _err := zlib.NewReader(bytes.NewBuffer(File.Content))
		if _err != nil {
			fmt.Printf("zlib.NewReader %s", _err.Error())
			return
		}
		buff := make([]byte, 0)
		totalRead := 0
		for true {
			tmp := make([]byte, 32768)
			nRead, _ := r.Read(tmp)
			if nRead == 0 {
				break
			}
			buff = append(buff, tmp[:nRead]...)
			totalRead += nRead
		}
		Md5 := md5.Sum(buff)
		EncodeMd5 := md5.Sum(File.Content)

		fmt.Printf("Recv File %s,%s,%s,%d,%d\n", File.FileName, hex.EncodeToString(Md5[:]), hex.EncodeToString(EncodeMd5[:]), totalRead, File.Len)
		ioutil.WriteFile(Path+"/"+File.FileName, buff, os.ModePerm)
	}
	go func() {
		AnalyiseChan <- Path
	}()
}

func AnlyiseMiniDump(MiniDumpPath string) {
	argv := make([]string, 0)
	argv = append(argv, fmt.Sprintf("-MiniDump=%s", MiniDumpPath+"/UE4Minidump.dmp"))
	if SymbolPath != nil {
		argv = append(argv, fmt.Sprintf("-DebugSymbols=;%s", *SymbolPath))
	}
	arrt := &os.ProcAttr{
		Files: make([]*os.File, 3),
	}
	stdout, _ := os.Create(MiniDumpPath + "/Callstack.txt")
	arrt.Files[1] = stdout
	process, err := os.StartProcess(*DumpAnlyisePath, argv, arrt)
	if err != nil {
		fmt.Printf("StartProcess %s", err.Error())
		return
	}
	process.Wait()
	stdout.Close()
}
