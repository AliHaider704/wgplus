package main

import (
	"embed"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"wgplus-win/internal/syswin"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	var startMinimized bool
	var selfCheck bool
	var noAutoElevate bool
	var elevatedRelaunch bool
	var inPlaceUpgraded bool
	var waitPid int
	var confArg string
	var forwardArgs []string

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		low := strings.ToLower(strings.TrimSpace(arg))
		switch low {
		case "--minimized":
			startMinimized = true
			forwardArgs = append(forwardArgs, arg)
		case "--self-check":
			selfCheck = true
		case "--no-auto-elevate":
			noAutoElevate = true
		case "--elevated-relaunch":
			elevatedRelaunch = true
		case "--in-place-upgraded":
			inPlaceUpgraded = true
		case "--wait-pid":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(strings.TrimSpace(args[i+1])); err == nil && p > 0 {
					waitPid = p
				}
				i++
			}
		default:
			if strings.HasSuffix(low, ".conf") {
				confArg = arg
			}
			forwardArgs = append(forwardArgs, arg)
		}
	}

	if waitPid > 0 {
		syswin.WaitForProcessExit(uint32(waitPid), 8*time.Second)
	}
	cleanupOldExecutableSidecars()
	if !selfCheck && !inPlaceUpgraded && !elevatedRelaunch {
		if maybeUpgradeInstalledCopyInPlace() {
			os.Exit(0)
		}
	}

	app, err := NewApp(startMinimized)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WireGuard Plus init error: %v\n", err)
		os.Exit(1)
	}
	if !selfCheck && !noAutoElevate && !isProcessElevated() && app.ShouldAlwaysRunAsAdmin() {
		relArgs := append([]string{"--no-auto-elevate"}, forwardArgs...)
		if rErr := syswin.RelaunchElevatedWithArgs(os.Getpid(), relArgs...); rErr == nil {
			os.Exit(0)
		}
	}
	if confArg != "" {
		app.SetPendingImportPath(confArg)
	}
	defer func() {
		if r := recover(); r != nil {
			app.recordRecoveredPanic("wails_main", r)
			panic(r)
		}
	}()

	if selfCheck {
		out, scErr := app.RunSelfCheck()
		if scErr != nil {
			fmt.Fprintf(os.Stderr, "self-check failed: %v\n", scErr)
			os.Exit(1)
		}
		fmt.Println(out)
		os.Exit(0)
	}

	err = wails.Run(&options.App{
		Title:             "WireGuard Plus",
		Width:             1020,
		Height:            740,
		MinWidth:          760,
		MinHeight:         580,
		StartHidden:       startMinimized,
		HideWindowOnClose: false, // controlled dynamically by OnBeforeClose
		BackgroundColour:  &options.RGBA{R: 21, G: 30, B: 39, A: 255},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:     app.startup,
		OnBeforeClose: app.beforeClose,
		OnShutdown:    app.shutdown,
		Bind: []interface{}{
			app,
		},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "org.telegram.wgplus.windows.singleinstance.v1",
			OnSecondInstanceLaunch: func(data options.SecondInstanceData) {
				for _, arg := range data.Args {
					if strings.HasSuffix(strings.ToLower(arg), ".conf") {
						if raw, rErr := os.ReadFile(arg); rErr == nil {
							_, _ = app.ImportConfText(string(raw), "")
						}
					}
				}
				app.ShowWindow()
			},
		},
		Windows: &windows.Options{
			Theme:               windows.Dark,
			WebviewUserDataPath: app.WebviewDataDir(),
			OnSuspend:           func() {},
			OnResume:            app.handleWakeRecovery,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "WireGuard Plus UI error: %v\n", err)
		os.Exit(1)
	}
}
