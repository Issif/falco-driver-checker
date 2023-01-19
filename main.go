package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/bitfield/script"
	"github.com/jedib0t/go-pretty/table"
	"github.com/joho/godotenv"
)

var (
	// operatingSystem string
	// driver        string
	lib           string
	hostRoot      string
	kernelRelease string
	kernelVersion string
	targetID      string
	jsonFile      string
	falcoVersions = map[string]string{
		"0.33.1": "3.0.1+driver",
		"0.33.0": "3.0.1+driver",
		"0.32.2": "2.0.0+driver",
		"0.32.1": "2.0.0+driver",
		"0.32.0": "39ae7d40496793cf3d3e7890c9bbdc202263836b",
		"0.31.1": "b7eb0dd65226a8dc254d228c8d950d07bf3521d2",
		"0.31.0": "319368f1ad778691164d33d59945e00c5752cd27",
		"0.30.0": "3aa7a83bf7b9e6229a3824e3fd1f4452d1e95cb4",
		"0.29.1": "17f5df52a7d9ed6bb12d3b1768460def8439936d",
		"0.29.0": "17f5df52a7d9ed6bb12d3b1768460def8439936d",
		"0.28.0": "5c0b863ddade7a45568c0ac97d037422c9efb750",
		"0.27.0": "5c0b863ddade7a45568c0ac97d037422c9efb750",
		"0.26.2": "2aa88dcf6243982697811df4c1b484bcbe9488a2",
		"0.26.1": "2aa88dcf6243982697811df4c1b484bcbe9488a2",
		"0.26.0": "2aa88dcf6243982697811df4c1b484bcbe9488a2",
		"0.25.0": "ae104eb20ff0198a5dcb0c91cc36c86e7c3f25c7",
		"0.24.0": "85c88952b018fdbce2464222c3303229f5bfcfad",
	}
)

const (
	defaultDriver = "ebpf"
	baseURL       = "https://download.falco.org/driver/site/"
)

func init() {
	lib = falcoVersions["0.33.1"]
	hostRoot = os.Getenv("HOST_ROOT")
	// driver = defaultDriver

	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		log.Fatal(err)
	}
	// arch = int8ToStr(uname.Machine[:]) // uname -m
	kernelRelease = int8ToStr(uname.Release[:]) // uname -r
	reg, _ := regexp.Compile("#[[:digit:]]+")
	kernelVersion = strings.ReplaceAll(reg.FindStringSubmatch(int8ToStr(uname.Version[:]))[0], "#", "") // uname -v | sed 's/#\([[:digit:]]\+\).*/\1/'
	getTargetID()
}

func main() {
	var l string
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SortBy([]table.SortBy{{Name: "version", Mode: table.Dsc}})
	t.AppendHeader(table.Row{"version", "ebpf", "kmod"})
	fmt.Println(generateName())
	for i, j := range falcoVersions {
		if l != j {
			downloadJSon()
			l = j
		}
		t.AppendRow(table.Row{
			i,
			exist("ebpf"),
			exist("module"),
		})
	}
	t.Render()
}

func getTargetID() {
	var OsID, VersionID, VariantID string
	if _, err := os.Stat(hostRoot + "/etc/os-release"); !errors.Is(err, os.ErrNotExist) {
		err := godotenv.Load(hostRoot + "/etc/os-release")
		if err != nil {
			log.Fatal(err)
		}
		OsID = os.Getenv("ID")
		VersionID = os.Getenv("VERSION_ID")
		VariantID = os.Getenv("VARIANT_ID")
	} else if _, err := os.Stat(hostRoot + "/etc/debian_version"); !errors.Is(err, os.ErrNotExist) {
		OsID = "debian"
	} else if _, err := os.Stat(hostRoot + "/etc/centos-release"); !errors.Is(err, os.ErrNotExist) {
		OsID = "centos"
	} else if _, err := os.Stat(hostRoot + "/etc/redhat-release"); !errors.Is(err, os.ErrNotExist) {
		OsID = "redhat"
	} else if _, err := os.Stat(hostRoot + "/etc/VERSION"); !errors.Is(err, os.ErrNotExist) {
		OsID = "minikube"
	}

	switch OsID {
	case "amzn":
		if VersionID == "2" {
			targetID = "amazonlinux2"
		} else {
			targetID = "amazonlinux"
		}
	case "ubuntu":
		reg, _ := regexp.Compile("([a-zA-Z]+)(-.*)?")
		if s := reg.FindStringSubmatch(kernelRelease)[0]; s != "" {
			targetID = "ubuntu-" + s
		} else {
			targetID = "ubuntu-generic"
		}
	case "flatcar":
		kernelRelease = VersionID
		targetID = strings.ToLower(OsID)
	case "minikube":
		reg, _ := regexp.Compile(`([0-9]+(\.[0-9]+){2})`)
		targetID = OsID
		v, err := script.File(hostRoot + "/etc/VERSION").MatchRegexp(reg).String()
		if err != nil {
			log.Fatal(err)
		}
		if v == "" {
			log.Fatal("Unable to extract minikube version from ${HOST_ROOT}/etc/VERSION")
		}
		kernelVersion = "1_" + v
	case "bottlerocket":
		targetID = OsID
		kernelVersion = "1_" + VersionID + "-" + strings.Split(VariantID, "-")[0]
	default:
		targetID = strings.ToLower(OsID)
	}
}

func downloadJSon() {
	u := fmt.Sprintf("%v%v.json", baseURL, url.QueryEscape(lib))
	r, err := http.Get(u)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}
	jsonFile = string(b)
}

func exist(d string) string {
	var ext string
	if d == "module" {
		ext = "ko"
	} else {
		ext = "o"
	}
	if strings.Contains(jsonFile, generateName()+"."+ext) {
		return "✓"
	}
	return "x"
}

func generateName() string {
	return fmt.Sprintf(
		"falco_%v_%v_%v",
		targetID,
		kernelRelease,
		kernelVersion,
	)
}

// A utility to convert the values to proper strings.
func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
