local wezterm = require 'wezterm'
local act = wezterm.action
local config = wezterm.config_builder()

-- ============================================================
-- Helpers
-- ============================================================

-- Read pixel dimensions from a PNG's IHDR chunk.
-- PNG layout: 8-byte signature + 4-byte chunk length + 4-byte 'IHDR'
-- + 4-byte width (big-endian) + 4-byte height (big-endian).
-- => width starts at offset 16, height at offset 20.
local function read_png_size(path)
  local f = io.open(path, 'rb')
  if not f then return nil end
  f:seek('set', 16)
  local raw = f:read(8)
  f:close()
  if not raw or #raw ~= 8 then return nil end
  local function be32(s, off)
    return s:byte(off)     * 0x1000000
         + s:byte(off + 1) * 0x10000
         + s:byte(off + 2) * 0x100
         + s:byte(off + 3)
  end
  return be32(raw, 1), be32(raw, 5)
end

-- ============================================================
-- Appearance
-- ============================================================

config.font_size = 14.5
config.tab_max_width = 32

-- Cleaner UI
config.window_padding = { left = 2, right = 2, top = 0, bottom = 0 }
config.hide_tab_bar_if_only_one_tab = true
config.use_fancy_tab_bar = false

-- Background: solid base color + Ditana logo overlay in the top-right corner,
-- rendered at the PNG's natural pixel size.
local logo_path = '/usr/share/pixmaps/ditana-logo-tiny.png'
local logo_w, logo_h = read_png_size(logo_path)

config.background = {
  {
    source = { Color = '#080d15' },
    width = '100%',
    height = '100%',
  },
}

if logo_w and logo_h then
  table.insert(config.background, {
    source = { File = logo_path },
    opacity = 0.4,
    horizontal_align = 'Right',
    vertical_align = 'Top',
    width = logo_w,
    height = logo_h,
    repeat_x = 'NoRepeat',
    repeat_y = 'NoRepeat',
  })
end

-- ============================================================
-- Selection / Clipboard
-- ============================================================

-- copy-on-select to system clipboard (ghostty: copy-on-select = clipboard).
-- wezterm by default copies to PrimarySelection on X11 only; this also
-- targets the regular clipboard so paste with Ctrl+V works everywhere.
config.mouse_bindings = {
  {
    event = { Up = { streak = 1, button = 'Left' } },
    mods = 'NONE',
    action = act.CompleteSelection 'ClipboardAndPrimarySelection',
  },
  -- Keep ctrl+click as URL opener (default behavior, kept explicit).
  {
    event = { Up = { streak = 1, button = 'Left' } },
    mods = 'CTRL',
    action = act.OpenLinkAtMouseCursor,
  },
}

-- ============================================================
-- Key bindings
-- ============================================================

config.keys = {
  -- ---------- Tabs ----------
  { key = 't',          mods = 'ALT',            action = act.SpawnTab 'CurrentPaneDomain' },
  { key = 'w',          mods = 'ALT',            action = act.CloseCurrentPane { confirm = false } },
  { key = 'LeftArrow',  mods = 'ALT',            action = act.ActivateTabRelative(-1) },
  { key = 'RightArrow', mods = 'ALT',            action = act.ActivateTabRelative(1) },
  { key = 'i',          mods = 'ALT',            action = act.MoveTabRelative(-1) },
  { key = 'o',          mods = 'ALT',            action = act.MoveTabRelative(1) },

  -- Tab rename prompt (ghostty: prompt_tab_title)
  {
    key = 'r',
    mods = 'ALT',
    action = act.PromptInputLine {
      description = 'Enter new tab title',
      action = wezterm.action_callback(function(window, _pane, line)
        if line then
          window:active_tab():set_title(line)
        end
      end),
    },
  },

  -- ---------- Pane splits (vim-style hjkl) ----------
  { key = 'l', mods = 'ALT|SHIFT', action = act.SplitPane { direction = 'Right', size = { Percent = 50 } } },
  { key = 'h', mods = 'ALT|SHIFT', action = act.SplitPane { direction = 'Left',  size = { Percent = 50 } } },
  { key = 'k', mods = 'ALT|SHIFT', action = act.SplitPane { direction = 'Up',    size = { Percent = 50 } } },
  { key = 'j', mods = 'ALT|SHIFT', action = act.SplitPane { direction = 'Down',  size = { Percent = 50 } } },

  -- ---------- Pane resize ----------
  -- ghostty used 32 (pixels). wezterm AdjustPaneSize counts cells, so 5 is a
  -- reasonable per-keypress step. Adjust to taste.
  { key = 'l', mods = 'CTRL|SHIFT|ALT', action = act.AdjustPaneSize { 'Right', 5 } },
  { key = 'h', mods = 'CTRL|SHIFT|ALT', action = act.AdjustPaneSize { 'Left',  5 } },
  { key = 'k', mods = 'CTRL|SHIFT|ALT', action = act.AdjustPaneSize { 'Up',    5 } },
  { key = 'j', mods = 'CTRL|SHIFT|ALT', action = act.AdjustPaneSize { 'Down',  5 } },

  -- ---------- Pane navigation ----------
  { key = 'l',          mods = 'ALT', action = act.ActivatePaneDirection 'Right' },
  { key = 'h',          mods = 'ALT', action = act.ActivatePaneDirection 'Left' },
  { key = 'k',          mods = 'ALT', action = act.ActivatePaneDirection 'Up' },
  { key = 'j',          mods = 'ALT', action = act.ActivatePaneDirection 'Down' },
  { key = 'UpArrow',    mods = 'ALT', action = act.ActivatePaneDirection 'Prev' },
  { key = 'DownArrow',  mods = 'ALT', action = act.ActivatePaneDirection 'Next' },

  -- ---------- Pane move (zellij-equivalent) ----------
  -- Alt+M opens an interactive pane selector; pick a letter to swap that
  -- pane with the active one. Focus stays in the pane that moved.
  { key = 'm', mods = 'ALT', action = act.PaneSelect { mode = 'SwapWithActiveKeepFocus' } },
  -- Bonus: rotate all panes within the current tab.
  { key = ',', mods = 'ALT', action = act.RotatePanes 'CounterClockwise' },
  { key = '.', mods = 'ALT', action = act.RotatePanes 'Clockwise' },

  -- ---------- Scroll to prompt (OSC 133) ----------
  -- Requires shell integration. nushell emits OSC 133 by default. There is a
  -- known interaction bug with some wezterm versions (every keystroke scrolls
  -- the buffer); workaround would be `osc133: false` in nushell config, but
  -- that disables this feature.
  { key = 'UpArrow',   mods = 'ALT|SHIFT', action = act.ScrollToPrompt(-1) },
  { key = 'DownArrow', mods = 'ALT|SHIFT', action = act.ScrollToPrompt(1) },

  -- ---------- Dump scrollback to file and open in $EDITOR ----------
  -- Equivalent to zellij's "edit scrollback". Honors $VISUAL first, falling
  -- back to $EDITOR, finally to vi. The editor is launched in a new tab so
  -- closing it returns the user to where they were.
  {
    key = 'e',
    mods = 'ALT',
    action = wezterm.action_callback(function(window, pane)
      local text = pane:get_lines_as_text(pane:get_dimensions().scrollback_rows)
      local tmp = os.getenv('TMPDIR') or '/tmp'
      local path = string.format('%s/wezterm-scrollback-%d.txt', tmp, os.time())
      local f, err = io.open(path, 'w')
      if not f then
        window:toast_notification('wezterm', 'Failed to write file: ' .. tostring(err), nil, 4000)
        return
      end
      f:write(text)
      f:close()
      local editor = os.getenv('VISUAL') or os.getenv('EDITOR') or 'vi'
      window:perform_action(
        act.SpawnCommandInNewTab { args = { editor, path } },
        pane
      )
    end),
  },

  -- ---------- Disable defaults (matches your ghostty unbinds) ----------
  { key = 'Home', mods = 'SHIFT',      action = act.DisableDefaultAssignment },
  { key = 'End',  mods = 'SHIFT',      action = act.DisableDefaultAssignment },
  { key = 'f',    mods = 'CTRL|SHIFT', action = act.DisableDefaultAssignment },
  { key = 'Tab',  mods = 'CTRL',       action = act.DisableDefaultAssignment },
  { key = 'Tab',  mods = 'CTRL|SHIFT', action = act.DisableDefaultAssignment },
}

-- Direct tab activation (zellij-equivalent: Alt+1..Alt+9 -> tab 0..8).
for i = 1, 9 do
  table.insert(config.keys, {
    key = tostring(i),
    mods = 'ALT',
    action = act.ActivateTab(i - 1),
  })
end

return config
