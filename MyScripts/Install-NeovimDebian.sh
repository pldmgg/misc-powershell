#!/bin/bash

# Check if the script is running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Halting!"
    exit 1
fi

ACTUAL_HOME=$(eval echo ~$SUDO_USER)

# Install prereqs
apt install git build-essential nodejs npm unzip -y
CONDA_PATH="/home/ttadmin/anaconda3/bin/conda"
if [ -d "$CONDA_PATH" ]; then
    echo "Path $CONDA_PATH exists. Anaconda is already installed."
else
    echo "Path $CONDA_PATH does not exist. Installing Anaconda."
    # Install Anaconda because this is the the python platform I'm most familiar with
    ANACONDA_URL=$(curl -s https://www.anaconda.com/download | grep -o 'https://repo.anaconda.com/archive/Anaconda3-.*-Linux-x86_64.sh' | head -n 1)
    INSTALLER_FILENAME=$(basename $ANACONDA_URL)
    # We should run the install NOT as root
    sudo -i -u "$SUDO_USER" bash -c "wget $ANACONDA_URL; bash $INSTALLER_FILENAME -b -p $ACTUAL_HOME/anaconda3"
    # The below runs "conda activate base" and then "conda init" as the appropriate user (not root)
    sudo -i -u "$SUDO_USER" bash -c 'eval "$('"$ACTUAL_HOME"'/anaconda3/bin/conda shell.bash hook)"; conda init'
fi

# Make sure you have access to python and pip
PYTHON_PATH="$ACTUAL_HOME/anaconda3/bin/python"
PIP_PATH="$ACTUAL_HOME/anaconda3/bin/pip"
if [ -d "$PYTHON_PATH" ] && [ -d "$PIP_PATH" ]; then
    echo "Both python and pip commands are available."
else
    echo "Either python or pip command is not found. Halting!"
    exit 1
fi

# Install pwsh because we like pwsh
apt install -y wget apt-transport-https software-properties-common
valid_versions=("22.04" "20.04" "18.04")
release_version=$(lsb_release -rs)
if [[ " ${valid_versions[@]} " =~ " $release_version " ]]; then
    wget https://packages.microsoft.com/config/ubuntu/$release_version/packages-microsoft-prod.deb
else
    echo "The release version is not valid for powershell install. Halting!"
    exit 1
fi
dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
apt update
apt install powershell -y

# Prep neovim
add-apt-repository ppa:neovim-ppa/unstable
apt update
apt install neovim
# Add python support to neovim
apt install python3-neovim

# Install neovim
cat << EOF > nvim_config_scaffold.sh
#!/bin/bash
mkdir -p $ACTUAL_HOME/.config/nvim
mkdir -p $ACTUAL_HOME/.config/nvim/after/plugin
mkdir -p $ACTUAL_HOME/.config/nvim/lua/$SUDO_USER
mkdir -p $ACTUAL_HOME/.config/nvim/plugin
mkdir -p $ACTUAL_HOME/.local/share/nvim/site/pack/packer/start
git clone --depth 1 https://github.com/wbthomason/packer.nvim ~/.local/share/nvim/site/pack/packer/start/packer.nvim
EOF
sudo -i -u "$SUDO_USER" bash -c "bash nvim_config_scaffold.sh"

# Setup config files
cat << EOF > "$ACTUAL_HOME/.config/nvim/init.lua"
require("$SUDO_USER")
print("hello")

local parser_config = require("nvim-treesitter.parsers").get_parser_configs()
parser_config.powershell = {
    install_info = {
        url = "https://github.com/jrsconfitto/tree-sitter-powershell",
        files = {"src/parser.c"}
    },
    filetype = "ps1",
    used_by = { "psm1", "psd1", "pssc", "psxml", "cdxml" }
}
EOF

cat << EOF > "$ACTUAL_HOME/.config/nvim/lua/$SUDO_USER/init.lua"
require("$SUDO_USER.remap")
require("$SUDO_USER.set")
print("hello from $SUDO_USER")
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/lua/$SUDO_USER/packer.lua"
-- This file can be loaded by calling `lua require('plugins')` from your init.vim

-- Only required if you have packer configured as `opt`
vim.cmd [[packadd packer.nvim]]

return require('packer').startup(function(use)
    -- Packer can manage itself
    use 'wbthomason/packer.nvim'

    use {
        'nvim-telescope/telescope.nvim', tag = '0.1.2',
        -- or, branch = '0.1.x',
        requires = { {'nvim-lua/plenary.nvim'} }
    }

    use {
        'rose-pine/neovim',
        as = 'rose-pine',
        config = function()
            vim.cmd('colorscheme rose-pine')
        end
    }

    use {'nvim-treesitter/nvim-treesitter', {run = ':TSUpdate'}}
    use {'nvim-treesitter/playground'}
    use {'theprimeagen/harpoon'}
    use {'mbbill/undotree'}
    use {'tpope/vim-fugitive'}

    use {
        'VonHeikemen/lsp-zero.nvim',
        branch = 'v2.x',
        requires = {
            -- LSP Support
            {'neovim/nvim-lspconfig'},             -- Required
            {'williamboman/mason.nvim'},           -- Optional
            {'williamboman/mason-lspconfig.nvim'}, -- Optional

            -- Autocompletion
            {'hrsh7th/nvim-cmp'},     -- Required
            {'hrsh7th/cmp-nvim-lsp'}, -- Required
            {'L3MON4D3/LuaSnip'},     -- Required
        }
    }

end)
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/lua/$SUDO_USER/remap.lua"
vim.g.mapleader = " "
vim.keymap.set("n", "<leader>pv", vim.cmd.Ex)

vim.keymap.set("n", "<leader>pv", ":Ex<CR>")
vim.keymap.set("n", "<leader>u", ":UndotreeShow<CR>")

vim.keymap.set("v", "J", ":m '>+1<CR>gv=gv")
vim.keymap.set("v", "K", ":m '<-2<CR>gv=gv")

vim.keymap.set("n", "Y", "yg$")
vim.keymap.set("n", "J", "mzJ`z")
vim.keymap.set("n", "<C-d>", "<C-d>zz")
vim.keymap.set("n", "<C-u>", "<C-u>zz")
vim.keymap.set("n", "n", "nzzzv")
vim.keymap.set("n", "N", "Nzzzv")

vim.keymap.set("n", "<leader>vwm", function()
    require("vim-with-me").StartVimWIthMe()
end)
vim.keymap.set("n", "<leader>svwm", function()
    require("vim-with-me").StopVimWithMe()
end)

-- greatest remap ever
vim.keymap.set("x", "<leader>p", "\"_dP")

-- next greatest remap ever
-- This has to do with separating out the copy buffer of vim
-- from the copy buffer of the system. Just "y" copies to
-- vim clipboard while <leader>y copies to system clipboard
vim.keymap.set("n", "<leader>y", "\"+y")
vim.keymap.set("v", "<leader>y", "\"+y")
vim.keymap.set("n", "<leader>Y", "\"+Y")

vim.keymap.set("n", "<leader>d", "\"_d")
vim.keymap.set("v", "<leader>d", "\"_d")

-- This is going to get me cancelled
vim.keymap.set("i", "<C-c>", "<Esc")

vim.keymap.set("n", "Q", "<nop>")
vim.keymap.set("n", "<C-f>", "<cmd>silent !tmux neww tmux-sessionizer<CR>")
vim.keymap.set("n", "<leader>f", function()
    vim.lsp.buf.format()
end)

vim.keymap.set("n", "<C-k>", "<cmd>cnext<CR>zz")
vim.keymap.set("n", "<C-j>", ",cmd?cprev<CR>zz")
vim.keymap.set("n", "<leader>k", "<cmd>lnext<CR>zz")
vim.keymap.set("n", "<leader>j", "<cmd>lprev<CR>zz")

vim.keymap.set("n", "<leader>s", ":%s/\\<<C-r><C-w>\\>/<C-r><C-w>/gI<Left><Left><Left>")
vim.keymap.set("n", "<leader>x", "<cmd>!chmod +x %<CR>", { silent = true })
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/lua/$SUDO_USER/set.lua"
--vim.opt.guicursor = ""

vim.opt.nu = true
vim.opt.relativenumber = true

vim.opt.tabstop = 4
vim.opt.softtabstop = 4
vim.opt.shiftwidth = 4
vim.opt.expandtab = true

vim.opt.smartindent = true

vim.opt.wrap = false

vim.opt.swapfile = false
vim.opt.backup = false
vim.opt.undodir = os.getenv("HOME") .. "/.vim/undodir"
vim.opt.undofile = true

vim.opt.hlsearch = false
vim.opt.incsearch = true

vim.opt.termguicolors = true

vim.opt.scrolloff = 8
vim.opt.signcolumn = "yes"
vim.opt.isfname:append("@-@")

vim.opt.updatetime = 50

vim.opt.colorcolumn = "80"

vim.g.mapleader = " "
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/after/plugin/color.lua"
function ColorMyPencils(color)
	color = color or "rose-pine"
	vim.cmd.colorscheme(color)

	vim.api.nvim_set_hl(0, "Normal", { bg = "none" })
	vim.api.nvim_set_hl(0, "NormalFloat", { bg = "none" })
end

ColorMyPencils()
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/after/plugin/fugitive.lua"
vim.keymap.set("n", "<leader>gs", vim.cmd.Git);
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/after/plugin/harpoon.lua"
local mark = require("harpoon.mark")
local ui = require("harpoon.ui")

vim.keymap.set("n", "<leader>a", mark.add_file)
vim.keymap.set("n", "<C-e>", ui.toggle_quick_menu)

vim.keymap.set('n', '<leader>1', function() ui.nav_file(1) end, opts)
vim.keymap.set('n', '<leader>2', function() ui.nav_file(2) end, opts)
vim.keymap.set('n', '<leader>3', function() ui.nav_file(3) end, opts)
vim.keymap.set('n', '<leader>4', function() ui.nav_file(4) end, opts)
vim.keymap.set('n', '<leader>5', function() ui.nav_file(5) end, opts)
vim.keymap.set('n', '<leader>6', function() ui.nav_file(6) end, opts)
vim.keymap.set('n', '<leader>7', function() ui.nav_file(7) end, opts)
vim.keymap.set('n', '<leader>8', function() ui.nav_file(8) end, opts)
vim.keymap.set('n', '<leader>9', function() ui.nav_file(9) end, opts)
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/after/plugin/lsp.lua"
local lsp = require('lsp-zero')

lsp.preset('recommended')

lsp.ensure_installed({
	'pyright',
	'lua_ls',
	'powershell_es'
})

local cmp = require('cmp')
local cmp_select = {behavior = cmp.SelectBehavior.Select}
local cmp_mappings = lsp.defaults.cmp_mappings({
	['<C-p>'] = cmp.mapping.select_prev_item(cmp_select),
	['<C-n>'] = cmp.mapping.select_next_item(cmp_select),
	['<C-y>'] = cmp.mapping.confirm({select = true}),
	['<C-Space>'] = cmp.mapping.complete(),
})

lsp.set_preferences({
	sign_icons = {}
})

lsp.setup_nvim_cmp({
	mapping = cmp_mappings
})

lsp.on_attach(function(client, bufnr)
	print("help")
	local opts = {buffer = bufnr, remap = false}
	
	vim.keymap.set("n", "gd", function() vim.lsp.buf.definition() end, opts)
	vim.keymap.set("n", "K", function() vim.lsp.buf.hover() end, opts)
	vim.keymap.set("n", "<leader>vws", function() vim.lsp.buf.workspace_symbol() end, opts)
	vim.keymap.set("n", "<leader>vd", function() vim.diagnostic.open_float() end, opts)
	vim.keymap.set("n", "[d", function() vim.diagnostic.goto_next() end, opts)
	vim.keymap.set("n","]d", function() vim.diagnostic.goto_prev() end, opts)
	vim.keymap.set("n", "<leader>vca", function() vim.lsp.buf.code_action() end, opts)
	vim.keymap.set("n", "<leader>vrr", function() vim.lsp.buf.references() end, opts)
	vim.keymap.set("n", "<leader>vrn", function() vim.lsp.buf.rename() end, opts)
	vim.keymap.set("i", "<C-h>", function() vim.lsp.buf.signature_help() end, opts)
end)

lsp.setup()
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/after/plugin/telescope.lua"
local builtin = require('telescope.builtin')
vim.keymap.set('n', '<leader>pf', builtin.find_files, {})
vim.keymap.set('n', '<C-p>', builtin.git_files, {})
vim.keymap.set('n', '<leader>ps', function()
	builtin.grep_string({ search = vim.fn.input("Grep > ") });
end)
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/after/plugin/treesitter.lua"
require'nvim-treesitter.configs'.setup {
    -- A list of parser names, or "all" (the five listed parsers should always be installed)
    ensure_installed = { "javascript", "typescript", "bash", "c_sharp", "css", "html", "dockerfile", "go", "json", "markdown", "powershell", "python", "rust", "svelte", "yaml", "zig", "c", "lua", "vim", "vimdoc", "query" },

    -- Install parsers synchronously (only applied to `ensure_installed`)
    sync_install = false,

    -- Automatically install missing parsers when entering buffer
    -- Recommendation: set to false if you don't have `tree-sitter` CLI installed locally
    auto_install = true,

    -- List of parsers to ignore installing (for "all")
    -- "help" is now called "vimdoc"
    ignore_install = { "help", "c#" },

    highlight = {
        enable = true,

        -- Setting this to true will run `:h syntax` and tree-sitter at the same time.
        -- Set this to `true` if you depend on 'syntax' being enabled (like for indentation).
        -- Using this option may slow down your editor, and you may see some duplicate highlights.
        -- Instead of true it can also be a list of languages
        additional_vim_regex_highlighting = false,
    },
}
EOF

cat << 'EOF' > "$ACTUAL_HOME/.config/nvim/after/plugin/undotree.lua"
vim.keymap.set("n", "<leader>u", vim.cmd.UndotreeToggle)
EOF

chown -R $SUDO_USER:$SUDO_USER "$ACTUAL_HOME/.config/nvim"

echo "Now run neovim via: cd $ACTUAL_HOME/.config/nvim && nvim ."
echo "Within neovim, open $ACTUAL_HOME/.config/nvim/lua/$SUDO_USER/packer.lua and run :so followed by :PackerSync"
