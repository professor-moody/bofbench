package tui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"bofbench/internal/arsenal"
	"bofbench/internal/lab"
	operationsvc "bofbench/internal/operation"
	packsvc "bofbench/internal/pack"
)

type model struct {
	tab                int
	projectCursor      int
	arsenalCursor      int
	runCursor          int
	labCursor          int
	viaCursor          int
	packCursor         int
	operationCursor    int
	topologyCursor     int
	labProfile         int
	argumentCursor     int
	projects           []string
	packs              []packsvc.Resolved
	operations         []operationsvc.Resolved
	operationRegistry  *operationsvc.Registry
	operationExpanded  bool
	operationParallel  int
	topologies         []string
	labProfiles        []string
	runArguments       []tuiArgument
	operationArguments []tuiArgument
	argumentProject    string
	argumentEditing    bool
	argumentBuffer     string
	arsenalRoot        string
	arsenal            []arsenal.Entry
	runs               []runEntry
	statusFilter       int
	runtimeFilter      int
	artifactFilter     bool
	width              int
	height             int
	message            string
	commandOutput      string
	running            bool
}

type tuiArgument struct {
	Name      string
	Type      string
	Sensitive bool
	Required  bool
	Value     string
}

type runEntry struct {
	Path           string
	Report         string
	Source         string
	Status         string
	Runtime        string
	Kind           string
	ExitState      string
	TaskID         string
	ExecutionState string
	OutputComplete bool
	Artifact       string
	Summary        string
	Events         []eventEntry
	Findings       []findingEntry
	ActualPath     []string
	ExpandedPath   []string
	SkippedSteps   []string
	MatchedRoutes  []string
	ChildReceipts  []string
	NestedCleanup  []string
	ParallelLanes  []string
	MaxConcurrency int
	ExecutionMode  string
	ExecutionWaves []string
	BlockedSteps   []string
	ReadinessRows  []string
	ActiveTasks    []string
	Cancellation   string
	DependencyRows []string
	ModTime        time.Time
}

type eventEntry struct {
	Type    string
	TimeMS  int64
	Status  string
	Message string
}

type findingEntry struct {
	Severity string
	Category string
	Detail   string
	Evidence string
	Source   string
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51"))
	tabStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("110"))
	hotStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	mutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
)

var tabs = []string{"build", "analyze", "arsenal", "run", "lab", "results", "packs", "prove", "topology", "operations", "help"}
var runVias = []string{"native", "lab", "sliver", "cobaltstrike"}
var labActions = [][]string{{"lab", "status"}, {"lab", "bootstrap"}, {"lab", "up"}, {"lab", "snapshot", "clean"}, {"lab", "restore", "clean"}}
var statusFilters = []string{"all", "pass", "fail", "setup_error", "analysis", "analyze_pass", "mixed_pass"}
var runtimeFilters = []string{"all", "auto", "windows-coff", "linux-elf", "darwin-macho", "wine-coff"}

func Run(stdout io.Writer) error {
	m := initialModel()
	p := tea.NewProgram(m, tea.WithOutput(stdout))
	_, err := p.Run()
	return err
}

func initialModel() model {
	root := "arsenal/trustedsec-sa"
	entries, _ := arsenal.List(root)
	runs := listRuns()
	registry, _ := packsvc.Load(packsvc.LoadOptions{Project: "."})
	var packs []packsvc.Resolved
	var operations []operationsvc.Resolved
	var operationRegistry *operationsvc.Registry
	if registry != nil {
		packs = registry.List()
		if loaded, err := operationsvc.Load(operationsvc.LoadOptions{Project: ".", PackRegistry: registry}); err == nil {
			operationRegistry = loaded
			operations = loaded.List()
		}
	}
	profiles, _ := lab.LoadProfiles(lab.ProfilesPath())
	labProfiles := lab.ProfileNames(profiles)
	labProfile := 0
	for index, name := range labProfiles {
		if name == profiles.Active {
			labProfile = index
			break
		}
	}
	return model{projects: listProjects(), arsenalRoot: root, arsenal: entries, runs: runs, packs: packs, operations: operations, operationRegistry: operationRegistry,
		topologies: lab.TopologyNames(profiles), labProfiles: labProfiles, labProfile: labProfile,
		operationParallel: 4, message: "new → add packs → build → analyze → run → export"}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.argumentEditing {
			arguments := &m.runArguments
			if m.tab == 9 {
				arguments = &m.operationArguments
			}
			switch msg.String() {
			case "esc":
				m.argumentEditing = false
				m.argumentBuffer = ""
			case "enter":
				if m.argumentCursor >= 0 && m.argumentCursor < len(*arguments) {
					(*arguments)[m.argumentCursor].Value = m.argumentBuffer
				}
				m.argumentEditing = false
				m.argumentBuffer = ""
			case "backspace":
				if len(m.argumentBuffer) > 0 {
					m.argumentBuffer = m.argumentBuffer[:len(m.argumentBuffer)-1]
				}
			default:
				if len(msg.Runes) > 0 {
					m.argumentBuffer += string(msg.Runes)
				}
			}
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab", "right":
			m.tab = (m.tab + 1) % len(tabs)
		case "shift+tab", "left":
			m.tab = (m.tab + len(tabs) - 1) % len(tabs)
		case "j", "down":
			m.moveCursor(1)
		case "k", "up":
			m.moveCursor(-1)
		case "home":
			m.setCursor(0)
		case "end":
			if max := m.currentCount(); max > 0 {
				m.setCursor(max - 1)
			}
		case "f":
			if m.tab == 5 {
				m.statusFilter = (m.statusFilter + 1) % len(statusFilters)
				m.runCursor = 0
			}
		case "t":
			if m.tab == 5 {
				m.runtimeFilter = (m.runtimeFilter + 1) % len(runtimeFilters)
				m.runCursor = 0
			}
		case "a":
			if m.tab == 5 {
				m.artifactFilter = !m.artifactFilter
				m.runCursor = 0
			}
		case "v":
			if m.tab == 3 || m.tab == 7 || m.tab == 9 {
				m.viaCursor = (m.viaCursor + 1) % len(runVias)
			}
		case "g":
			if m.tab == 9 {
				m.operationExpanded = !m.operationExpanded
			}
		case "+":
			if m.tab == 9 && m.operationParallel < 16 {
				m.operationParallel++
			}
		case "-":
			if m.tab == 9 && m.operationParallel > 1 {
				m.operationParallel--
			}
		case "l":
			if (m.tab == 3 || m.tab == 7 || m.tab == 9) && len(m.labProfiles) > 0 {
				m.labProfile = (m.labProfile + 1) % len(m.labProfiles)
			}
		case "[":
			arguments := m.runArguments
			if m.tab == 9 {
				arguments = m.operationArguments
			}
			if (m.tab == 3 || m.tab == 9) && len(arguments) > 0 {
				m.argumentCursor = (m.argumentCursor + len(arguments) - 1) % len(arguments)
			}
		case "]":
			arguments := m.runArguments
			if m.tab == 9 {
				arguments = m.operationArguments
			}
			if (m.tab == 3 || m.tab == 9) && len(arguments) > 0 {
				m.argumentCursor = (m.argumentCursor + 1) % len(arguments)
			}
		case "e":
			if m.tab == 3 {
				m.refreshRunArguments()
				if len(m.runArguments) > 0 {
					m.argumentEditing = true
					m.argumentBuffer = m.runArguments[m.argumentCursor].Value
				}
			} else if m.tab == 9 {
				m.refreshOperationArguments()
				if len(m.operationArguments) > 0 {
					m.argumentEditing = true
					m.argumentBuffer = m.operationArguments[m.argumentCursor].Value
				}
			}
		case "c":
			if m.tab == 6 && !m.running {
				if project, ok := m.selectedProject(); ok {
					if capability, ok := m.selectedPack(); ok {
						m.running = true
						command := []string{"add", project, capability.Qualified}
						m.message = "$ bofbench " + strings.Join(command, " ")
						return m, executeBOFBench(command)
					}
				}
			}
		case "p":
			if m.tab == 9 && !m.running {
				if operation, ok := m.selectedOperation(); ok {
					command := []string{"operation", "prove", operation.Qualified, "--via", runVias[m.viaCursor]}
					command = append(command, "--parallelism", strconv.Itoa(max(1, m.operationParallel)))
					if (runVias[m.viaCursor] == "lab" || runVias[m.viaCursor] == "sliver") && len(m.labProfiles) > 0 {
						command = append(command, "--lab", m.labProfiles[m.labProfile])
					}
					m.running = true
					m.commandOutput = ""
					m.message = "$ bofbench " + strings.Join(command, " ")
					return m, executeBOFBench(command)
				}
			}
		case "x":
			if m.tab == 9 && !m.running {
				if operation, ok := m.selectedOperation(); ok {
					command := []string{"operation", "test", operation.Qualified, "--compiler", "mingw"}
					m.running = true
					m.commandOutput = ""
					m.message = "$ bofbench " + strings.Join(command, " ")
					return m, executeBOFBench(command)
				}
			}
		case "enter":
			if !m.running {
				if command := m.currentCommand(); len(command) > 0 {
					m.running = true
					m.commandOutput = ""
					m.message = "$ bofbench " + strings.Join(command, " ")
					return m, executeBOFBench(command)
				}
			}
		case "r":
			next := initialModel()
			next.tab = m.tab
			next.arsenalCursor = min(m.arsenalCursor, max(0, len(next.arsenal)-1))
			next.runCursor = m.runCursor
			next.projectCursor = min(m.projectCursor, max(0, len(next.projects)-1))
			next.labCursor = m.labCursor
			next.viaCursor = m.viaCursor
			next.statusFilter = m.statusFilter
			next.runtimeFilter = m.runtimeFilter
			next.artifactFilter = m.artifactFilter
			next.operationExpanded = m.operationExpanded
			next.operationParallel = m.operationParallel
			m = next
		}
	case commandResultMsg:
		m.running = false
		m.commandOutput = strings.TrimSpace(msg.Output)
		if msg.Err != nil {
			m.message = "command failed: " + msg.Err.Error()
		} else {
			m.message = "command complete"
		}
		m.runs = listRuns()
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("BOFBENCH"))
	b.WriteString(" ")
	b.WriteString(m.renderTabs())
	b.WriteString("\n")
	if m.message != "" {
		b.WriteString(mutedStyle.Render(m.message))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	switch m.tab {
	case 0:
		b.WriteString(m.viewBuild())
	case 1:
		b.WriteString(m.viewAnalyzer())
	case 2:
		b.WriteString(m.viewArsenal())
	case 3:
		b.WriteString(m.viewRun())
	case 4:
		b.WriteString(m.viewLab())
	case 5:
		b.WriteString(m.viewRuns())
	case 6:
		b.WriteString(m.viewPacks())
	case 7:
		b.WriteString(m.viewProof())
	case 8:
		b.WriteString(m.viewTopologies())
	case 9:
		b.WriteString(m.viewOperations())
	case 10:
		b.WriteString(m.viewHelp())
	}
	if m.commandOutput != "" {
		b.WriteString("\n\n")
		b.WriteString(statusStyle.Render("LAST COMMAND"))
		b.WriteString("\n")
		b.WriteString(shorten(m.commandOutput, 1200))
	}
	b.WriteString("\n\n")
	b.WriteString(mutedStyle.Render(m.footer()))
	return b.String()
}

func (m model) renderTabs() string {
	var out []string
	for i, tab := range tabs {
		if i == m.tab {
			out = append(out, hotStyle.Render("["+tab+"]"))
		} else {
			out = append(out, tabStyle.Render(tab))
		}
	}
	return strings.Join(out, "  ")
}

func (m model) footer() string {
	base := "tab switch  j/k select  enter run  r refresh  q quit"
	if m.tab == 3 || m.tab == 9 {
		base += "  v runtime  l lab  [/] argument  e edit"
	}
	if m.tab == 6 {
		base += "  c compose into selected project"
	}
	if m.tab == 7 {
		base += "  v runtime  l lab"
	}
	if m.tab == 5 {
		base += "  f status filter  t runtime filter  a selected artifact"
	}
	return base
}

func (m model) currentCount() int {
	switch m.tab {
	case 0, 1, 3:
		return len(m.projects)
	case 2:
		return len(m.arsenal)
	case 4:
		return len(labActions)
	case 5:
		return len(m.filteredRuns())
	case 6, 7:
		return len(m.packs)
	case 8:
		return len(m.topologies)
	case 9:
		return len(m.operations)
	default:
		return 0
	}
}

func (m *model) moveCursor(delta int) {
	switch m.tab {
	case 0, 1, 3:
		if len(m.projects) == 0 {
			return
		}
		m.projectCursor = clamp(m.projectCursor+delta, 0, len(m.projects)-1)
	case 2:
		if len(m.arsenal) == 0 {
			return
		}
		m.arsenalCursor = clamp(m.arsenalCursor+delta, 0, len(m.arsenal)-1)
	case 4:
		m.labCursor = clamp(m.labCursor+delta, 0, len(labActions)-1)
	case 5:
		count := len(m.filteredRuns())
		if count == 0 {
			return
		}
		m.runCursor = clamp(m.runCursor+delta, 0, count-1)
	case 6, 7:
		if len(m.packs) > 0 {
			m.packCursor = clamp(m.packCursor+delta, 0, len(m.packs)-1)
		}
	case 8:
		if len(m.topologies) > 0 {
			m.topologyCursor = clamp(m.topologyCursor+delta, 0, len(m.topologies)-1)
		}
	case 9:
		if len(m.operations) > 0 {
			m.operationCursor = clamp(m.operationCursor+delta, 0, len(m.operations)-1)
			m.operationArguments = nil
			m.argumentCursor = 0
		}
	}
}

func (m *model) setCursor(value int) {
	switch m.tab {
	case 0, 1, 3:
		if len(m.projects) > 0 {
			m.projectCursor = clamp(value, 0, len(m.projects)-1)
		}
	case 2:
		if len(m.arsenal) > 0 {
			m.arsenalCursor = clamp(value, 0, len(m.arsenal)-1)
		}
	case 4:
		m.labCursor = clamp(value, 0, len(labActions)-1)
	case 5:
		count := len(m.filteredRuns())
		if count > 0 {
			m.runCursor = clamp(value, 0, count-1)
		}
	case 6, 7:
		if len(m.packs) > 0 {
			m.packCursor = clamp(value, 0, len(m.packs)-1)
		}
	case 8:
		if len(m.topologies) > 0 {
			m.topologyCursor = clamp(value, 0, len(m.topologies)-1)
		}
	case 9:
		if len(m.operations) > 0 {
			m.operationCursor = clamp(value, 0, len(m.operations)-1)
			m.operationArguments = nil
			m.argumentCursor = 0
		}
	}
}

type commandResultMsg struct {
	Output string
	Err    error
}

func executeBOFBench(args []string) tea.Cmd {
	return func() tea.Msg {
		executable, err := os.Executable()
		if err != nil {
			return commandResultMsg{Err: err}
		}
		output, runErr := exec.Command(executable, args...).CombinedOutput()
		return commandResultMsg{Output: string(output), Err: runErr}
	}
}

func (m model) currentCommand() []string {
	switch m.tab {
	case 0:
		if project, ok := m.selectedProject(); ok {
			return []string{"build", project}
		}
	case 1:
		if project, ok := m.selectedProject(); ok {
			return []string{"analyze", project}
		}
	case 2:
		if entry, ok := m.selectedArsenalEntry(); ok {
			if object := selectedObject(entry); object != "" {
				return []string{"analyze", object}
			}
		}
	case 3:
		if project, ok := m.selectedProject(); ok {
			command := []string{"run", project, "--via", runVias[m.viaCursor]}
			if (runVias[m.viaCursor] == "lab" || runVias[m.viaCursor] == "sliver") && len(m.labProfiles) > 0 {
				command = append(command, "--lab", m.labProfiles[m.labProfile])
			}
			for _, argument := range m.runArguments {
				if argument.Value != "" {
					command = append(command, "--arg", argument.Name+"="+argument.Value)
				}
			}
			return command
		}
	case 4:
		if m.labCursor >= 0 && m.labCursor < len(labActions) {
			return append([]string(nil), labActions[m.labCursor]...)
		}
	case 6:
		if capability, ok := m.selectedPack(); ok {
			return []string{"pack", "show", capability.Qualified}
		}
	case 7:
		if capability, ok := m.selectedPack(); ok {
			command := []string{"pack", "prove", capability.Qualified, "--via", runVias[m.viaCursor]}
			if len(m.topologies) > 0 {
				command = append(command, "--topology", m.topologies[m.topologyCursor])
			} else if (runVias[m.viaCursor] == "lab" || runVias[m.viaCursor] == "sliver") && len(m.labProfiles) > 0 {
				command = append(command, "--lab", m.labProfiles[m.labProfile])
			}
			return command
		}
	case 8:
		if len(m.topologies) > 0 {
			return []string{"lab", "topology", "status", m.topologies[m.topologyCursor]}
		}
	case 9:
		if operation, ok := m.selectedOperation(); ok {
			command := []string{"operation", "run", operation.Qualified, "--via", runVias[m.viaCursor], "--parallelism", strconv.Itoa(max(1, m.operationParallel))}
			if (runVias[m.viaCursor] == "lab" || runVias[m.viaCursor] == "sliver") && len(m.labProfiles) > 0 {
				command = append(command, "--lab", m.labProfiles[m.labProfile])
			}
			for _, argument := range m.operationArguments {
				if argument.Value != "" {
					command = append(command, "--arg", argument.Name+"="+argument.Value)
				}
			}
			return command
		}
	}
	return nil
}

func listProjects() []string {
	entries, err := os.ReadDir("bofs")
	if err != nil {
		return nil
	}
	var projects []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		root := filepath.Join("bofs", entry.Name())
		matches, _ := filepath.Glob(filepath.Join(root, "*.c"))
		if len(matches) > 0 {
			projects = append(projects, root)
		}
	}
	sort.Strings(projects)
	return projects
}

func (m model) selectedProject() (string, bool) {
	if len(m.projects) == 0 {
		return "", false
	}
	index := clamp(m.projectCursor, 0, len(m.projects)-1)
	return m.projects[index], true
}

func (m model) renderProjects() string {
	if len(m.projects) == 0 {
		return "No BOF projects found. Start with:\n\n  bofbench new fieldcheck --pack host-discovery"
	}
	var b strings.Builder
	limit := visibleRows(m.height, 8, 14)
	start, end := windowRange(len(m.projects), m.projectCursor, limit)
	for index := start; index < end; index++ {
		prefix := "  "
		if index == m.projectCursor {
			prefix = "> "
		}
		fmt.Fprintf(&b, "%s%s\n", prefix, m.projects[index])
	}
	return b.String()
}

func (m model) viewBuild() string {
	var b strings.Builder
	b.WriteString("BUILD A BOF\n")
	b.WriteString(mutedStyle.Render("Select a project. Enter compiles its resolved capability packs."))
	b.WriteString("\n\n")
	b.WriteString(m.renderProjects())
	if project, ok := m.selectedProject(); ok {
		fmt.Fprintf(&b, "\nAction\n  bofbench build %s\n\nAdd capability\n  bofbench add %s <pack>\n", project, project)
	}
	return b.String()
}

func (m model) viewRun() string {
	var b strings.Builder
	b.WriteString("RUN A BOF\n")
	fmt.Fprintf(&b, "%s\n\n", mutedStyle.Render("Choose a project and runtime. Edit typed arguments here; sensitive values are never echoed."))
	b.WriteString(m.renderProjects())
	if project, ok := m.selectedProject(); ok {
		labName := "active"
		if len(m.labProfiles) > 0 {
			labName = m.labProfiles[m.labProfile]
		}
		fmt.Fprintf(&b, "\nRuntime   %s  Lab %s\nAction    bofbench run %s --via %s\n", hotStyle.Render(runVias[m.viaCursor]), labName, project, runVias[m.viaCursor])
		fmt.Fprintf(&b, "Cleanup   bofbench run %s --via %s --cleanup\n", project, runVias[m.viaCursor])
		fmt.Fprintf(&b, "%s\n", mutedStyle.Render("Operational packs expose target, payload, guard_mode, overwrite, backup, restore, and cleanup as ordinary typed arguments when supported."))
		if m.argumentProject != project {
			fmt.Fprintf(&b, "\nArguments  press e to load and edit this project's typed arguments\n")
		} else if len(m.runArguments) == 0 {
			fmt.Fprintf(&b, "\nArguments  none\n")
		} else {
			b.WriteString("\nArguments  [/] select, e edit\n")
			for index, argument := range m.runArguments {
				prefix := "  "
				if index == m.argumentCursor {
					prefix = "> "
				}
				value := argument.Value
				if argument.Sensitive && value != "" {
					value = "<redacted>"
				}
				if value == "" {
					value = "<unset>"
				}
				if m.argumentEditing && index == m.argumentCursor {
					value = m.argumentBuffer
					if argument.Sensitive && value != "" {
						value = strings.Repeat("•", len([]rune(value)))
					}
				}
				required := ""
				if argument.Required {
					required = " required"
				}
				fmt.Fprintf(&b, "%s%-24s %-8s%s %s\n", prefix, argument.Name, argument.Type, required, value)
			}
		}
	}
	return b.String()
}

func (m *model) refreshRunArguments() {
	project, ok := m.selectedProject()
	if !ok || m.argumentProject == project {
		return
	}
	lock, _, err := packsvc.LoadLock(project)
	if err != nil {
		m.runArguments = nil
		m.argumentProject = project
		return
	}
	seen := map[string]bool{}
	var arguments []tuiArgument
	for _, record := range lock.Packs {
		for _, argument := range record.Arguments {
			if seen[argument.Name] {
				continue
			}
			seen[argument.Name] = true
			arguments = append(arguments, tuiArgument{Name: argument.Name, Type: argument.Type, Sensitive: argument.Sensitive, Required: argument.Required, Value: argument.Default})
		}
	}
	m.runArguments = arguments
	m.argumentProject = project
	m.argumentCursor = 0
}

func (m model) selectedPack() (packsvc.Resolved, bool) {
	if len(m.packs) == 0 {
		return packsvc.Resolved{}, false
	}
	return m.packs[clamp(m.packCursor, 0, len(m.packs)-1)], true
}

func (m model) viewPacks() string {
	if len(m.packs) == 0 {
		return "No capability catalogs are available. Add one with:\n\n  bofbench catalog add <path>"
	}
	var b strings.Builder
	b.WriteString("CAPABILITY PACKS\n")
	b.WriteString(mutedStyle.Render("Browse resolved catalogs. Enter inspects a pack; c composes it into the selected BOF project."))
	b.WriteString("\n\n")
	limit := visibleRows(m.height, 10, 16)
	start, end := windowRange(len(m.packs), m.packCursor, limit)
	for index := start; index < end; index++ {
		item := m.packs[index]
		prefix := "  "
		if index == m.packCursor {
			prefix = "> "
		}
		fmt.Fprintf(&b, "%s%-44s %-8s %s\n", prefix, item.Qualified, item.Document.Tier, shorten(item.Document.Summary, 70))
	}
	if item, ok := m.selectedPack(); ok {
		project, hasProject := m.selectedProject()
		b.WriteString("\nSelected\n")
		fmt.Fprintf(&b, "  Can do: %s\n  Effects: %s\n  Works with: %s\n", strings.Join(item.Document.Capabilities, ", "), strings.Join(item.Document.Effects, ", "), strings.Join(item.Document.TargetSupport, ", "))
		fmt.Fprintf(&b, "  Inspect: bofbench pack show %s\n", item.Qualified)
		if hasProject {
			fmt.Fprintf(&b, "  Compose: bofbench add %s %s\n", project, item.Qualified)
		}
		fmt.Fprintf(&b, "  Search:  bofbench pack search <capability>\n")
	}
	return b.String()
}

func (m model) viewProof() string {
	if len(m.packs) == 0 {
		return "No capability packs are available for proof."
	}
	var b strings.Builder
	b.WriteString("PROVE A CAPABILITY\n")
	b.WriteString(mutedStyle.Render("Run the selected pack's declared proof, collect an exact-hash receipt, and independently verify cleanup."))
	b.WriteString("\n\n")
	limit := visibleRows(m.height, 10, 16)
	start, end := windowRange(len(m.packs), m.packCursor, limit)
	for index := start; index < end; index++ {
		item := m.packs[index]
		prefix := "  "
		if index == m.packCursor {
			prefix = "> "
		}
		coverage := "no proof"
		if len(item.Document.ProofCases) > 0 {
			coverage = fmt.Sprintf("%d proof", len(item.Document.ProofCases))
		}
		fmt.Fprintf(&b, "%s%-44s %s\n", prefix, item.Qualified, coverage)
	}
	if item, ok := m.selectedPack(); ok {
		labName := "active"
		if len(m.labProfiles) > 0 {
			labName = m.labProfiles[m.labProfile]
		}
		fmt.Fprintf(&b, "\nRuntime %s  Lab %s\n", hotStyle.Render(runVias[m.viaCursor]), labName)
		fmt.Fprintf(&b, "Action  bofbench pack prove %s --via %s\n", item.Qualified, runVias[m.viaCursor])
	}
	return b.String()
}

func (m model) viewTopologies() string {
	if len(m.topologies) == 0 {
		return "MULTI-HOST TOPOLOGIES\n\nNo topology is configured. Start with:\n\n  bofbench lab topology add dedicated-standalone --execution devbox --target dedicated"
	}
	var b strings.Builder
	b.WriteString("MULTI-HOST TOPOLOGIES\n")
	b.WriteString(mutedStyle.Render("Topology files store profile names only; credentials remain in the selected transports."))
	b.WriteString("\n\n")
	for index, name := range m.topologies {
		prefix := "  "
		if index == m.topologyCursor {
			prefix = "> "
		}
		fmt.Fprintf(&b, "%s%s\n", prefix, name)
	}
	name := m.topologies[clamp(m.topologyCursor, 0, len(m.topologies)-1)]
	fmt.Fprintf(&b, "\nAction  bofbench lab topology status %s\nProof   bofbench pack prove --all --via lab --topology %s\n", name, name)
	return b.String()
}

func (m model) selectedOperation() (operationsvc.Resolved, bool) {
	if len(m.operations) == 0 {
		return operationsvc.Resolved{}, false
	}
	return m.operations[clamp(m.operationCursor, 0, len(m.operations)-1)], true
}

func (m *model) refreshOperationArguments() {
	operation, ok := m.selectedOperation()
	if !ok {
		return
	}
	if len(m.operationArguments) > 0 {
		return
	}
	for _, input := range operation.Document.Inputs {
		m.operationArguments = append(m.operationArguments, tuiArgument{Name: input.Name, Type: input.Type, Sensitive: input.Sensitive, Required: input.Required, Value: input.Default})
	}
	m.argumentCursor = 0
}

func (m model) viewOperations() string {
	if len(m.operations) == 0 {
		return "OPERATIONS\n\nNo operation definitions are available."
	}
	var b strings.Builder
	b.WriteString("MULTI-STEP OPERATIONS\n")
	b.WriteString(mutedStyle.Render("Run result-aware pack workflows with typed inputs, pinned routes, resume, and reverse cleanup."))
	b.WriteString("\n\n")
	limit := visibleRows(m.height, 12, 16)
	start, end := windowRange(len(m.operations), m.operationCursor, limit)
	for index := start; index < end; index++ {
		item := m.operations[index]
		prefix := "  "
		if index == m.operationCursor {
			prefix = "> "
		}
		fmt.Fprintf(&b, "%s%-42s %d steps  %s\n", prefix, item.Qualified, len(item.Document.Steps), shorten(item.Document.Summary, 62))
	}
	if item, ok := m.selectedOperation(); ok {
		labName := "active"
		if len(m.labProfiles) > 0 {
			labName = m.labProfiles[m.labProfile]
		}
		fmt.Fprintf(&b, "\nExecution %s  Runtime %s  Lab %s  Parallelism %d (+/-)\nRun      bofbench operation run %s --via %s --parallelism %d\n", operationsvc.ExecutionMode(item.Document), hotStyle.Render(runVias[m.viaCursor]), labName, max(1, m.operationParallel), item.Qualified, runVias[m.viaCursor], max(1, m.operationParallel))
		fmt.Fprintf(&b, "Test [x] bofbench operation test %s\nProve[p] bofbench operation prove %s --via %s\n", item.Qualified, item.Qualified, runVias[m.viaCursor])
		fmt.Fprintf(&b, "Watch    bofbench operation watch runs/<id>/operation.json --follow\nCancel   bofbench operation cancel runs/<id>/operation.json [--cleanup]\nResume   bofbench operation resume runs/<id>/operation.json\nCleanup  bofbench operation cleanup runs/<id>/operation.json\n")
		if m.operationRegistry != nil {
			graph, err := m.operationRegistry.Graph(item, "text", m.operationExpanded)
			if err == nil {
				mode := "collapsed"
				if m.operationExpanded {
					mode = "expanded"
				}
				fmt.Fprintf(&b, "\nRoutes  %s (g toggles)\n", mode)
				for _, line := range strings.Split(strings.TrimSpace(graph), "\n") {
					if strings.Contains(line, " -> ") {
						fmt.Fprintf(&b, "  %s\n", line)
					}
				}
			}
		}
		children := []string{}
		lanes := []string{}
		dependencies := []string{}
		for _, step := range item.Document.Steps {
			if len(step.DependsOn) == 0 && len(step.DependsOnReady) == 0 && operationsvc.IsDAG(item.Document) {
				dependencies = append(dependencies, step.ID+" ← ready root")
			} else if len(step.DependsOn) > 0 {
				dependencies = append(dependencies, step.ID+" ← "+strings.Join(step.DependsOn, ", "))
			}
			if len(step.DependsOnReady) > 0 {
				dependencies = append(dependencies, step.ID+" ⇠ ready("+strings.Join(step.DependsOnReady, ", ")+")")
			}
			if step.Mode == "background" {
				dependencies = append(dependencies, step.ID+" background: ready → active → terminal")
			}
			if step.Operation != "" {
				children = append(children, step.ID+" → "+step.Operation)
			}
			if step.Parallel != nil {
				for _, branch := range step.Parallel.Branches {
					target := branch.Pack
					if branch.Operation != "" {
						target = "operation:" + branch.Operation
						children = append(children, step.ID+"/"+branch.ID+" → "+branch.Operation)
					}
					lanes = append(lanes, step.ID+"/"+branch.ID+" → "+target)
				}
			}
		}
		if len(dependencies) > 0 {
			b.WriteString("\nDependency readiness\n")
			for _, dependency := range dependencies {
				fmt.Fprintf(&b, "  %s\n", dependency)
			}
		}
		if len(lanes) > 0 {
			b.WriteString("\nParallel lanes\n")
			for _, lane := range lanes {
				fmt.Fprintf(&b, "  %s\n", lane)
			}
		}
		if len(children) > 0 {
			b.WriteString("\nChild operations\n")
			for _, child := range children {
				fmt.Fprintf(&b, "  %s\n", child)
			}
		}
		if len(m.operationArguments) == 0 {
			b.WriteString("\nArguments  press e to load and edit typed operation inputs\n")
		} else {
			b.WriteString("\nArguments  [/] select, e edit\n")
			for index, arg := range m.operationArguments {
				prefix := "  "
				if index == m.argumentCursor {
					prefix = "> "
				}
				value := arg.Value
				if arg.Sensitive && value != "" {
					value = "<redacted>"
				}
				if value == "" {
					value = "<unset>"
				}
				required := ""
				if arg.Required {
					required = " required"
				}
				fmt.Fprintf(&b, "%s%-24s %-8s%s %s\n", prefix, arg.Name, arg.Type, required, value)
			}
		}
	}
	return b.String()
}

func (m model) viewLab() string {
	var b strings.Builder
	b.WriteString("WINDOWS LAB\n")
	b.WriteString(mutedStyle.Render("Bootstrap an existing VM first; provider actions use the saved lab configuration."))
	b.WriteString("\n\n")
	for index, action := range labActions {
		prefix := "  "
		if index == m.labCursor {
			prefix = "> "
		}
		fmt.Fprintf(&b, "%s bofbench %s\n", prefix, strings.Join(action, " "))
	}
	return b.String()
}

func (m model) viewArsenal() string {
	if len(m.arsenal) == 0 {
		return "No arsenal entries found. Try:\n\n  bofbench fetch trustedsec-sa"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Arsenal browser: %s (%d entries)\n\n", m.arsenalRoot, len(m.arsenal))
	limit := visibleRows(m.height, 10, 18)
	start, end := windowRange(len(m.arsenal), m.arsenalCursor, limit)
	for i := start; i < end; i++ {
		entry := m.arsenal[i]
		prefix := "  "
		if i == m.arsenalCursor {
			prefix = "> "
		}
		fmt.Fprintf(&b, "%s%-28s %-8s %s\n", prefix, entry.Name, archLabel(entry), entry.Path)
	}
	if start > 0 || end < len(m.arsenal) {
		fmt.Fprintf(&b, "\nshowing %d-%d of %d\n", start+1, end, len(m.arsenal))
	}
	if entry, ok := m.selectedArsenalEntry(); ok {
		b.WriteString("\n")
		b.WriteString(m.renderArsenalDetail(entry))
	}
	return b.String()
}

func (m model) renderArsenalDetail(entry arsenal.Entry) string {
	var b strings.Builder
	object := selectedObject(entry)
	b.WriteString("Selected\n")
	fmt.Fprintf(&b, "  name: %s\n", entry.Name)
	fmt.Fprintf(&b, "  path: %s\n", entry.Path)
	if entry.X64 != "" {
		fmt.Fprintf(&b, "  x64:  %s\n", entry.X64)
	}
	if entry.X86 != "" {
		fmt.Fprintf(&b, "  x86:  %s\n", entry.X86)
	}
	b.WriteString("\nActions\n")
	if object == "" {
		fmt.Fprintf(&b, "  bofbench build %s --arch x64\n", entry.Path)
		fmt.Fprintf(&b, "  bofbench test %s --select %s\n", m.arsenalRoot, entry.Name)
		return b.String()
	}
	for _, line := range []string{
		"bofbench analyze " + object,
		"bofbench analyze " + object + " --format md",
		"bofbench run " + object + " --via native",
		"bofbench test " + m.arsenalRoot + " --select " + entry.Name + " --runtime windows-coff",
		"bofbench export " + object + " --for raw",
	} {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	return b.String()
}

func (m model) viewAnalyzer() string {
	var b strings.Builder
	b.WriteString("ANALYZE CAPABILITIES\n")
	b.WriteString(mutedStyle.Render("Enter builds the selected project and explains Can do, Needs, Effects, arguments, and runtimes."))
	b.WriteString("\n\n")
	b.WriteString(m.renderProjects())
	if project, ok := m.selectedProject(); ok {
		fmt.Fprintf(&b, "\nAction\n  bofbench analyze %s\n", project)
	}
	findings := recentFindings(m.runs, 8)
	if len(findings) > 0 {
		b.WriteString("\nRecent analysis cues\n")
		for _, finding := range findings {
			line := fmt.Sprintf("%s/%s: %s", finding.Severity, finding.Category, finding.Detail)
			if finding.Source != "" {
				line += " (" + finding.Source + ")"
			}
			fmt.Fprintf(&b, "  %s\n", shorten(line, 110))
		}
	}
	return b.String()
}

func (m model) viewRuns() string {
	filtered := m.filteredRuns()
	if len(filtered) == 0 {
		return fmt.Sprintf("No run history for status=%s runtime=%s artifact=%s.\n\nRun `bofbench analyze`, `bofbench build`, `bofbench run`, or press `f`/`t`/`a` to change filters.",
			statusFilters[m.statusFilter], runtimeFilters[m.runtimeFilter], m.artifactFilterLabel())
	}
	var b strings.Builder
	b.WriteString("PREDICTED ↔ OBSERVED RESULTS\n")
	fmt.Fprintf(&b, "Recent runs  status=%s  runtime=%s  artifact=%s  (%d/%d)\n\n",
		statusFilters[m.statusFilter], runtimeFilters[m.runtimeFilter], m.artifactFilterLabel(), len(filtered), len(m.runs))
	limit := visibleRows(m.height, 10, 16)
	start, end := windowRange(len(filtered), m.runCursor, limit)
	for i := start; i < end; i++ {
		run := filtered[i]
		prefix := "  "
		if i == m.runCursor {
			prefix = "> "
		}
		status := run.Status
		if status == "" {
			status = "-"
		}
		runtime := run.Runtime
		if runtime == "" {
			runtime = "-"
		}
		fmt.Fprintf(&b, "%s%-12s %-13s %-10s %s\n", prefix, status, runtime, run.Source, run.Path)
	}
	if start > 0 || end < len(filtered) {
		fmt.Fprintf(&b, "\nshowing %d-%d of %d\n", start+1, end, len(filtered))
	}
	if m.runCursor < len(filtered) {
		b.WriteString("\n")
		b.WriteString(renderRunDetail(filtered[m.runCursor]))
	}
	return b.String()
}

func renderRunDetail(run runEntry) string {
	var b strings.Builder
	b.WriteString("Selected report\n")
	fmt.Fprintf(&b, "  path:   %s\n", run.Path)
	if run.Report != "" {
		fmt.Fprintf(&b, "  report: %s\n", run.Report)
	}
	if run.Artifact != "" {
		fmt.Fprintf(&b, "  object: %s\n", run.Artifact)
	}
	fmt.Fprintf(&b, "  status: %s\n", emptyDash(run.Status))
	if run.Runtime != "" || run.Kind != "" || run.ExitState != "" {
		fmt.Fprintf(&b, "  runtime/kind/exit: %s / %s / %s\n", emptyDash(run.Runtime), emptyDash(run.Kind), emptyDash(run.ExitState))
	}
	if run.ExecutionState != "" || run.TaskID != "" {
		fmt.Fprintf(&b, "  task: %s  state=%s  output_complete=%t\n", emptyDash(run.TaskID), emptyDash(run.ExecutionState), run.OutputComplete)
	}
	if len(run.ActualPath) > 0 {
		fmt.Fprintf(&b, "  path:   %s\n", strings.Join(run.ActualPath, " → "))
		if len(run.ExpandedPath) > 0 && strings.Join(run.ExpandedPath, "|") != strings.Join(run.ActualPath, "|") {
			fmt.Fprintf(&b, "  expanded: %s\n", strings.Join(run.ExpandedPath, " → "))
		}
		if len(run.SkippedSteps) > 0 {
			fmt.Fprintf(&b, "  skipped: %s\n", strings.Join(run.SkippedSteps, ", "))
		}
		if len(run.MatchedRoutes) > 0 {
			fmt.Fprintf(&b, "  outcomes: %s\n", strings.Join(run.MatchedRoutes, ", "))
		}
	}
	if len(run.ChildReceipts) > 0 {
		fmt.Fprintf(&b, "  child receipts: %s\n", strings.Join(run.ChildReceipts, ", "))
	}
	if len(run.NestedCleanup) > 0 {
		fmt.Fprintf(&b, "  nested cleanup: %s\n", strings.Join(run.NestedCleanup, ", "))
	}
	if len(run.ParallelLanes) > 0 {
		fmt.Fprintf(&b, "  parallel lanes: %s\n", strings.Join(run.ParallelLanes, ", "))
		fmt.Fprintf(&b, "  max concurrency: %d\n", run.MaxConcurrency)
	}
	if run.ExecutionMode != "" {
		fmt.Fprintf(&b, "  execution: %s\n", run.ExecutionMode)
	}
	if len(run.ExecutionWaves) > 0 {
		fmt.Fprintf(&b, "  waves: %s\n", strings.Join(run.ExecutionWaves, " | "))
		fmt.Fprintf(&b, "  max concurrency: %d\n", run.MaxConcurrency)
	}
	if len(run.DependencyRows) > 0 {
		fmt.Fprintf(&b, "  dependency state: %s\n", strings.Join(run.DependencyRows, ", "))
	}
	if len(run.ReadinessRows) > 0 {
		fmt.Fprintf(&b, "  readiness: %s\n", strings.Join(run.ReadinessRows, ", "))
	}
	if len(run.ActiveTasks) > 0 {
		fmt.Fprintf(&b, "  active tasks: %s\n", strings.Join(run.ActiveTasks, ", "))
	}
	if run.Cancellation != "" {
		fmt.Fprintf(&b, "  cancellation: %s\n", run.Cancellation)
	}
	if len(run.BlockedSteps) > 0 {
		fmt.Fprintf(&b, "  blocked: %s\n", strings.Join(run.BlockedSteps, ", "))
	}
	if run.Summary != "" {
		fmt.Fprintf(&b, "  summary: %s\n", run.Summary)
	}
	if len(run.Events) > 0 {
		b.WriteString("\nEvents\n")
		start := max(0, len(run.Events)-6)
		for _, event := range run.Events[start:] {
			fmt.Fprintf(&b, "  %4dms %-14s %-10s %s\n", event.TimeMS, event.Type, event.Status, shorten(event.Message, 90))
		}
	}
	if len(run.Findings) > 0 {
		b.WriteString("\nFindings\n")
		limit := min(len(run.Findings), 5)
		for i := 0; i < limit; i++ {
			finding := run.Findings[i]
			fmt.Fprintf(&b, "  %s/%s %s\n", finding.Severity, finding.Category, shorten(finding.Detail, 100))
		}
	}
	if run.Artifact != "" {
		b.WriteString("\nFollow-up\n")
		fmt.Fprintf(&b, "  bofbench inspect %s\n", run.Artifact)
		fmt.Fprintf(&b, "  bofbench analyze %s --format md\n", run.Artifact)
	}
	return b.String()
}

func (m model) viewStage() string {
	var b strings.Builder
	b.WriteString("Staging wizard\n\n")
	if entry, ok := m.selectedArsenalEntry(); ok {
		object := selectedObject(entry)
		if object != "" {
			fmt.Fprintf(&b, "Selected artifact: %s\n\n", object)
			for _, target := range []string{"cobaltstrike", "sliver", "raw"} {
				fmt.Fprintf(&b, "  bofbench export %s --for %s\n", object, target)
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("Targets\n\n")
	b.WriteString("  cobaltstrike  emits object + .cna wrapper\n")
	b.WriteString("  sliver        emits object + extension metadata\n")
	b.WriteString("  raw           emits object + operator notes\n")
	return b.String()
}

func (m model) viewHelp() string {
	return `Help

Every Enter action invokes the same BOFBench command used by the CLI.

Controls:

  tab/right        next view
  shift+tab/left   previous view
  j/down           move down
  k/up             move up
  home/end         jump within current list
  enter            execute the selected action
  v                cycle native/lab/Sliver/Cobalt Strike in Run
  l                cycle configured lab profiles in Run and Prove
  [ / ]            select a typed argument in Run
  e                edit the selected argument; sensitive input is masked
  c                compose the selected pack into the selected project
  x / p            test or prove the selected operation
  f                cycle status filter in Results
  t                cycle runtime filter in Results
  r                refresh arsenal and run history
  q                quit

Fast paths:

  bofbench new fieldcheck --pack host-discovery,token-context
  bofbench add bofs/fieldcheck process-discovery
  bofbench build bofs/fieldcheck
  bofbench analyze <artifact>
  bofbench run bofs/fieldcheck --via lab
  bofbench export bofs/fieldcheck --for sliver
`
}

func (m model) selectedArsenalEntry() (arsenal.Entry, bool) {
	if len(m.arsenal) == 0 {
		return arsenal.Entry{}, false
	}
	idx := m.arsenalCursor
	if idx < 0 {
		idx = 0
	}
	if idx >= len(m.arsenal) {
		idx = len(m.arsenal) - 1
	}
	return m.arsenal[idx], true
}

func (m model) filteredRuns() []runEntry {
	status := statusFilters[m.statusFilter]
	runtime := runtimeFilters[m.runtimeFilter]
	artifact := ""
	if m.artifactFilter {
		if entry, ok := m.selectedArsenalEntry(); ok {
			artifact = selectedObject(entry)
		}
	}
	out := make([]runEntry, 0, len(m.runs))
	for _, run := range m.runs {
		if status != "all" && run.Status != status {
			continue
		}
		if runtime != "all" && run.Runtime != runtime {
			continue
		}
		if artifact != "" && !matchesArtifact(run, artifact) {
			continue
		}
		out = append(out, run)
	}
	return out
}

func (m model) artifactFilterLabel() string {
	if !m.artifactFilter {
		return "all"
	}
	if entry, ok := m.selectedArsenalEntry(); ok {
		if object := selectedObject(entry); object != "" {
			return filepath.Base(object)
		}
		return entry.Name
	}
	return "selected"
}

func matchesArtifact(run runEntry, artifact string) bool {
	if artifact == "" {
		return true
	}
	if run.Artifact == artifact {
		return true
	}
	base := filepath.Base(artifact)
	return strings.Contains(run.Artifact, base) || strings.Contains(run.Path, strings.TrimSuffix(base, filepath.Ext(base)))
}

func listRuns() []runEntry {
	entries, err := os.ReadDir("runs")
	if err != nil {
		return nil
	}
	var out []runEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		path := filepath.Join("runs", entry.Name())
		out = append(out, readRunEntry(path, info.ModTime()))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.After(out[j].ModTime) })
	return out
}

func readRunEntry(path string, modTime time.Time) runEntry {
	run := runEntry{Path: path, ModTime: modTime}
	for _, name := range []string{"operation.json", "result.json", "lab-smoke.json", "analysis.json"} {
		report := filepath.Join(path, name)
		b, err := os.ReadFile(report)
		if err != nil {
			continue
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			continue
		}
		run.Report = report
		run.Source = strings.TrimSuffix(name, ".json")
		applyRunFields(&run, v)
		switch name {
		case "operation.json":
			run.Source = "operation"
			run.ActualPath = stringSliceField(v, "actual_path")
			run.ExpandedPath = stringSliceField(v, "expanded_path")
			run.SkippedSteps = stringSliceField(v, "skipped_steps")
			run.MaxConcurrency = int(intField(v, "max_observed_concurrency"))
			run.ExecutionMode = stringField(v, "execution")
			run.BlockedSteps = stringSliceField(v, "blocked_steps")
			run.Cancellation = stringField(v, "cancellation_state")
			if waves, ok := v["execution_waves"].([]any); ok {
				for _, rawWave := range waves {
					wave, ok := rawWave.(map[string]any)
					if !ok {
						continue
					}
					steps := stringSliceField(wave, "steps")
					run.ExecutionWaves = append(run.ExecutionWaves, fmt.Sprintf("%d:%s=%s", intField(wave, "index"), strings.Join(steps, "+"), emptyDash(stringField(wave, "state"))))
				}
			}
			if steps, ok := v["steps"].([]any); ok {
				for _, raw := range steps {
					step, ok := raw.(map[string]any)
					if !ok {
						continue
					}
					if outcome := stringField(step, "matched_outcome"); outcome != "" {
						run.MatchedRoutes = append(run.MatchedRoutes, stringField(step, "id")+"="+outcome)
					}
					dependencies := stringSliceField(step, "depends_on")
					readyDependencies := stringSliceField(step, "depends_on_ready")
					if len(dependencies) > 0 || len(readyDependencies) > 0 || stringField(step, "state") == "blocked" {
						label := stringField(step, "id") + "←" + strings.Join(dependencies, "+") + "=" + emptyDash(stringField(step, "state"))
						if len(readyDependencies) > 0 {
							label += "(ready:" + strings.Join(readyDependencies, "+") + ")"
						}
						if blocked := stringSliceField(step, "blocked_by"); len(blocked) > 0 {
							label += "(blocked-by:" + strings.Join(blocked, "+") + ")"
						}
						run.DependencyRows = append(run.DependencyRows, label)
					}
					if mode := stringField(step, "mode"); mode == "background" || stringField(step, "ready_state") != "" {
						label := stringField(step, "id") + "=" + emptyDash(stringField(step, "ready_state"))
						if readyAt := stringField(step, "ready_at"); readyAt != "" {
							label += "@" + readyAt
						}
						run.ReadinessRows = append(run.ReadinessRows, label)
					}
					if runtimeReceipt, ok := step["runtime_receipt"].(map[string]any); ok {
						state := stringField(runtimeReceipt, "execution_state")
						if state == "submitted" || state == "running" {
							run.ActiveTasks = append(run.ActiveTasks, stringField(step, "id")+"="+stringField(runtimeReceipt, "task_id"))
						}
					}
					if child := stringField(step, "child_receipt"); child != "" {
						run.ChildReceipts = append(run.ChildReceipts, stringField(step, "id")+"="+child)
						run.NestedCleanup = append(run.NestedCleanup, stringField(step, "id")+"="+emptyDash(stringField(step, "child_cleanup_state")))
					}
					if parallel, ok := step["parallel"].(map[string]any); ok {
						group := stringField(step, "id")
						if branches, ok := parallel["branches"].([]any); ok {
							for _, rawBranch := range branches {
								branch, ok := rawBranch.(map[string]any)
								if !ok {
									continue
								}
								label := group + "/" + stringField(branch, "id") + "=" + emptyDash(stringField(branch, "state"))
								if started := stringField(branch, "started_at"); started != "" {
									label += "@" + started
								}
								run.ParallelLanes = append(run.ParallelLanes, label)
								if child := stringField(branch, "child_receipt"); child != "" {
									run.ChildReceipts = append(run.ChildReceipts, group+"/"+stringField(branch, "id")+"="+child)
									run.NestedCleanup = append(run.NestedCleanup, group+"/"+stringField(branch, "id")+"="+emptyDash(stringField(branch, "child_cleanup_state")))
								}
							}
						}
					}
				}
			}
			if len(run.ExpandedPath) > 0 {
				run.Summary = strings.Join(run.ExpandedPath, " → ")
			} else {
				run.Summary = strings.Join(run.ActualPath, " → ")
			}
		case "analysis.json":
			run.Source = "analysis"
			if run.Status == "" {
				run.Status = "analysis"
			}
			run.Artifact = stringField(v, "path")
			run.Findings = parseFindings(v["findings"], "")
		case "lab-smoke.json":
			run.Source = "lab-smoke"
			run.Summary = labSummary(v)
		case "result.json":
			parseResultReport(&run, v)
		}
		if run.Status == "" {
			run.Status = "unknown"
		}
		return run
	}
	run.Source = "directory"
	return run
}

func applyRunFields(run *runEntry, v map[string]any) {
	if s := stringField(v, "status"); s != "" {
		run.Status = s
	}
	if s := stringField(v, "runtime"); s != "" {
		run.Runtime = s
	}
	if s := stringField(v, "kind"); s != "" {
		run.Kind = s
	}
	if s := stringField(v, "exit_state"); s != "" {
		run.ExitState = s
	}
	if s := stringField(v, "task_id"); s != "" {
		run.TaskID = s
	}
	if s := stringField(v, "execution_state"); s != "" {
		run.ExecutionState = s
	}
	if value, ok := v["output_complete"].(bool); ok {
		run.OutputComplete = value
	}
	if s := stringField(v, "object"); s != "" {
		run.Artifact = s
	}
	run.Events = parseEvents(v["events"])
}

func parseResultReport(run *runEntry, v map[string]any) {
	if root := stringField(v, "root"); root != "" {
		run.Source = "arsenal-test"
		run.Artifact = root
		run.Summary = testSummary(v["summary"])
		run.Findings = parseArsenalFindings(v["results"])
		return
	}
	if run.Artifact != "" {
		run.Source = "run"
	} else {
		run.Source = "test"
	}
}

func parseEvents(v any) []eventEntry {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]eventEntry, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, eventEntry{
			Type:    stringField(m, "type"),
			TimeMS:  intField(m, "time_ms"),
			Status:  stringField(m, "status"),
			Message: stringField(m, "message"),
		})
	}
	return out
}

func parseArsenalFindings(v any) []findingEntry {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []findingEntry
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		source := stringField(m, "name")
		analysis, ok := m["analysis"].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, parseFindings(analysis["findings"], source)...)
	}
	return out
}

func parseFindings(v any, source string) []findingEntry {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]findingEntry, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, findingEntry{
			Severity: stringField(m, "severity"),
			Category: stringField(m, "category"),
			Detail:   stringField(m, "detail"),
			Evidence: stringField(m, "evidence"),
			Source:   source,
		})
	}
	return out
}

func recentFindings(runs []runEntry, limit int) []findingEntry {
	var out []findingEntry
	for _, run := range runs {
		for _, finding := range run.Findings {
			out = append(out, finding)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func testSummary(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d pass, %d analyze-only, %d fail, %d total",
		intField(m, "passed"), intField(m, "analyze_only"), intField(m, "failed"), intField(m, "total"))
}

func labSummary(v map[string]any) string {
	if steps, ok := v["steps"].([]any); ok {
		return fmt.Sprintf("%d lab steps", len(steps))
	}
	return ""
}

func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func intField(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}

func stringSliceField(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, value := range raw {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func selectedObject(entry arsenal.Entry) string {
	if entry.X64 != "" {
		return entry.X64
	}
	return entry.X86
}

func archLabel(entry arsenal.Entry) string {
	var arch []string
	if entry.X64 != "" {
		arch = append(arch, "x64")
	}
	if entry.X86 != "" {
		arch = append(arch, "x86")
	}
	if len(arch) == 0 {
		return "-"
	}
	return strings.Join(arch, ",")
}

func visibleRows(height, fallback, cap int) int {
	if height <= 0 {
		return fallback
	}
	rows := height / 3
	if rows < fallback {
		return fallback
	}
	if rows > cap {
		return cap
	}
	return rows
}

func windowRange(total, cursor, limit int) (int, int) {
	if total <= 0 {
		return 0, 0
	}
	if limit <= 0 || limit > total {
		limit = total
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= total {
		cursor = total - 1
	}
	start := cursor - limit + 1
	if start < 0 {
		start = 0
	}
	end := start + limit
	if end > total {
		end = total
		start = max(0, end-limit)
	}
	return start, end
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shorten(s string, limit int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if limit <= 0 || len(s) <= limit {
		return s
	}
	if limit <= 3 {
		return s[:limit]
	}
	return s[:limit-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
