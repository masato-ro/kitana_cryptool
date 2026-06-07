#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/provider.h>

#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Tabs.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Progress.H>
#include <FL/Fl_Value_Slider.H>
#include <FL/Fl_Sys_Menu_Bar.H>

#include "ui_callbacks.h"

// ===================================================================
// Global UI Control Pointers
// ===================================================================
// --- Tab Framework ---
Fl_Tabs* g_main_tabs         = nullptr;

// --- Tab 1: AES ---
Fl_Choice* g_mode_choice     = nullptr;
Fl_Input* g_input_file      = nullptr;
Fl_Input* g_output_file     = nullptr;
Fl_Secret_Input* g_password_input  = nullptr;
Fl_Button* g_btn_start       = nullptr;
Fl_Button* g_btn_clear       = nullptr;

// --- Tab 2: KeyGen ---
Fl_Choice* g_keygen_bits        = nullptr;
Fl_Input* g_priv_key_path      = nullptr;
Fl_Input* g_pub_key_path       = nullptr;
Fl_Check_Button* g_ssh_key_check        = nullptr;
Fl_Input* g_ssh_comment_input        = nullptr;
Fl_Button* g_btn_generate_key   = nullptr;
Fl_Button* g_btn_copy_ssh       = nullptr;
Fl_Button* g_btn_keygen_clear   = nullptr;

// --- Tab 3: PasswdGen ---
Fl_Value_Slider* g_passwd_len_slider = nullptr;
Fl_Check_Button* g_chk_upper = nullptr;
Fl_Check_Button* g_chk_lower = nullptr;
Fl_Check_Button* g_chk_digits = nullptr;
Fl_Check_Button* g_chk_symbols = nullptr;
Fl_Input* g_generated_passwd_input = nullptr;
Fl_Button* g_btn_generate_passwd = nullptr;
Fl_Button* g_btn_copy_passwd = nullptr;
Fl_Button* g_btn_passwd_clear = nullptr;
Fl_Progress* g_passwd_strength = nullptr;

// --- Tab 4: Hash Matrix Components ---
Fl_Choice* g_hash_mode_choice  = nullptr;
Fl_Choice* g_hash_alg_choice   = nullptr;
Fl_Input* g_hash_input_source = nullptr;
Fl_Button* g_btn_hash_browse   = nullptr;
Fl_Input* g_hash_result_input = nullptr;
Fl_Button* g_btn_hash_compute  = nullptr;
Fl_Button* g_btn_hash_copy     = nullptr;
Fl_Button* g_btn_hash_clear    = nullptr;
Fl_Button* g_btn_hash_compare = nullptr;

// --- Shared Components ---
Fl_Progress* g_progress_bar    = nullptr;
Fl_Text_Display* g_console         = nullptr;
Fl_Text_Buffer* g_text_buffer     = nullptr;
std::mutex       g_console_mutex;

// ===================================================================
// Menu Bar Definition
// ===================================================================
Fl_Menu_Item menu_table[] = {
    {"&File", 0, nullptr, nullptr, FL_SUBMENU},
      {"&Exit", FL_ALT + 'q', MenuBarCallback, const_cast<char*>("Exit"), 0},
      {nullptr},
    {"&Mode", 0, nullptr, nullptr, FL_SUBMENU},
      {"AES Encrypt/Decrypt", FL_ALT + '1', MenuBarCallback, const_cast<char*>("Tab_AES"), 0},
      {"KeyGen", FL_ALT + '2', MenuBarCallback, const_cast<char*>("Tab_KeyGen"), 0},
      {"PasswdGen", FL_ALT + '3', MenuBarCallback, const_cast<char*>("Tab_PasswdGen"), 0},
      {"Hash Matrix", FL_ALT + '4', MenuBarCallback, const_cast<char*>("Tab_Hash"), 0},
      {nullptr},
    {"&Help", 0, nullptr, nullptr, FL_SUBMENU},
      {"&About", 0, MenuBarCallback, const_cast<char*>("About"), 0},
      {nullptr},
    {nullptr}
};

// ===================================================================
// Main Entry Point
// ===================================================================
int main(int argc, char** argv) {
    OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER_load(nullptr, "base");

    Fl::lock();
    Fl::scheme("none");
    Fl::background(240, 240, 240);
    Fl::background2(255, 255, 255);

    static const char* font_name = "Microsoft JhengHei";
    Fl::set_font(FL_FREE_FONT, font_name);

    auto* win = new Fl_Window(620, 555, "Kitana Cryptool - Crypto Engine Matrix v0.1");
    win->begin();

    // Create top menu bar (Height 25)
    auto* menu_bar = new Fl_Sys_Menu_Bar(0, 0, 620, 25);
    menu_bar->menu(menu_table);
    menu_bar->labelfont(FL_FREE_FONT);
    menu_bar->textfont(FL_FREE_FONT);

    // Move Tabs Y coordinate down by 25 to avoid menu bar
    g_main_tabs = new Fl_Tabs(10, 35, 600, 225);
    g_main_tabs->labelfont(FL_FREE_FONT);
    g_main_tabs->labelsize(13);
    g_main_tabs->begin();

    // ===============================================================
    // TAB 1: AES Encrypt/Decrypt
    // ===============================================================
    auto* aes_group = new Fl_Group(10, 60, 600, 200, "AES Encrypt/Decrypt");
    aes_group->begin();
        g_mode_choice = new Fl_Choice(120, 80, 470, 25, "Mode:");
        g_mode_choice->add("Encrypt");
        g_mode_choice->add("Decrypt");
        g_mode_choice->value(0);

        g_input_file = new Fl_Input(120, 115, 380, 25, "Input File:");
        auto* btn_browse_in = new Fl_Button(510, 115, 80, 25, "Browse...");
        btn_browse_in->callback(OnBrowseInputClick);

        g_output_file = new Fl_Input(120, 150, 380, 25, "Output File:");
        auto* btn_browse_out = new Fl_Button(510, 150, 80, 25, "Browse...");
        btn_browse_out->callback(OnBrowseOutputClick);

        g_password_input = new Fl_Secret_Input(120, 185, 470, 25, "Password:");

        g_btn_start = new Fl_Button(30, 220, 100, 30, "Start");
        g_btn_start->callback(OnStartClick);

        g_btn_clear = new Fl_Button(140, 220, 100, 30, "Clear");
        g_btn_clear->callback(OnClearClick);
    aes_group->end();

    // ===============================================================
    // TAB 2: KeyGen
    // ===============================================================
    auto* keygen_group = new Fl_Group(10, 60, 600, 200, "KeyGen");
    keygen_group->begin();
        g_keygen_bits = new Fl_Choice(160, 80, 430, 25, "Key Length");
        g_keygen_bits->add("1024");
        g_keygen_bits->add("2048");
        g_keygen_bits->add("4096");
        g_keygen_bits->value(1);

        g_priv_key_path = new Fl_Input(160, 115, 340, 25, "Private Key Output");
        auto* btn_b_priv = new Fl_Button(510, 115, 80, 25, "Browse...");
        btn_b_priv->callback(OnBrowsePrivateClick);

        g_pub_key_path = new Fl_Input(160, 150, 340, 25, "Public Key Output");
        auto* btn_b_pub = new Fl_Button(510, 150, 80, 25, "Browse...");
        btn_b_pub->callback(OnBrowsePublicClick);

        g_ssh_key_check = new Fl_Check_Button(30, 185, 250, 25, "Generate OpenSSH Public Key.");
        g_ssh_key_check->callback(OnSshCheckClick);

        g_ssh_comment_input = new Fl_Input(420, 185, 170, 25, "Comment:");
        g_ssh_comment_input->deactivate();

        g_btn_generate_key = new Fl_Button(30, 220, 110, 30, "Generate Key");
        g_btn_generate_key->callback(OnGenerateKeyClick);

        g_btn_copy_ssh = new Fl_Button(150, 220, 130, 30, "Copy SSH Pub Key");
        g_btn_copy_ssh->callback(OnCopySSHClick);

        g_btn_keygen_clear = new Fl_Button(290, 220, 100, 30, "Clear");
        g_btn_keygen_clear->callback(OnKeyGenClearClick);
    keygen_group->end();
    keygen_group->hide();

    // ===============================================================
    // TAB 3: PasswdGen
    // ===============================================================
    auto* passwdgen_group = new Fl_Group(10, 60, 600, 200, "PasswdGen");
    passwdgen_group->begin();
        g_passwd_len_slider = new Fl_Value_Slider(120, 80, 470, 25, "Length:");
        g_passwd_len_slider->type(FL_HORIZONTAL);
        g_passwd_len_slider->bounds(8, 64);
        g_passwd_len_slider->value(16);
        g_passwd_len_slider->step(1);
        g_passwd_len_slider->align(FL_ALIGN_LEFT);

        g_chk_upper = new Fl_Check_Button(30, 115, 120, 25, "Uppercase");
        g_chk_upper->value(1);

        g_chk_lower = new Fl_Check_Button(160, 115, 120, 25, "Lowercase");
        g_chk_lower->value(1);

        g_chk_digits = new Fl_Check_Button(290, 115, 120, 25, "Digits");
        g_chk_digits->value(1);

        g_chk_symbols = new Fl_Check_Button(420, 115, 120, 25, "Symbols");
        g_chk_symbols->value(1);

        g_generated_passwd_input = new Fl_Input(120, 150, 470, 25, "Password:");

        g_passwd_strength = new Fl_Progress(120, 185, 470, 15, "");
        g_passwd_strength->minimum(0);
        g_passwd_strength->maximum(100);
        g_passwd_strength->color(fl_rgb_color(200, 200, 200));

        g_btn_generate_passwd = new Fl_Button(30, 220, 150, 30, "Generate Password");
        g_btn_generate_passwd->callback(OnGeneratePasswordClick);

        g_btn_copy_passwd = new Fl_Button(190, 220, 150, 30, "Copy Password");
        g_btn_copy_passwd->callback(OnCopyPasswordClick);

        g_btn_passwd_clear = new Fl_Button(350, 220, 100, 30, "Clear");
        g_btn_passwd_clear->callback(OnPasswdClearClick);

    passwdgen_group->end();
    passwdgen_group->hide();

    // ===============================================================
    // TAB 4: Hash Matrix
    // ===============================================================
    auto* hash_group = new Fl_Group(10, 60, 600, 200, "Hash Matrix");
    hash_group->begin();
        g_hash_mode_choice = new Fl_Choice(120, 80, 170, 25, "Target Type:");
        g_hash_mode_choice->add("File Path");
        g_hash_mode_choice->add("Plain Text");
        g_hash_mode_choice->value(0);
        g_hash_mode_choice->callback(OnHashModeChangeClick);

        g_hash_alg_choice = new Fl_Choice(420, 80, 170, 25, "Algorithm:");
        g_hash_alg_choice->add("MD5");
        g_hash_alg_choice->add("SHA-1");
        g_hash_alg_choice->add("SHA-256");
        g_hash_alg_choice->add("SHA-3-256");
        g_hash_alg_choice->value(2);

        g_hash_input_source = new Fl_Input(120, 115, 380, 25, "Source Input:");

        g_btn_hash_browse = new Fl_Button(510, 115, 80, 25, "Browse...");
        g_btn_hash_browse->callback(OnHashBrowseClick);

        g_hash_result_input = new Fl_Input(120, 150, 380, 25, "Hash Result:");
        g_hash_result_input->color(fl_rgb_color(245, 245, 245));
        g_hash_result_input->readonly(1);

        g_btn_hash_compare = new Fl_Button(510, 150, 80, 25, "Compare...");
        g_btn_hash_compare->callback(OnHashCompareFileClick);

        g_btn_hash_compute = new Fl_Button(30, 220, 140, 30, "Compute Hash");
        g_btn_hash_compute->callback(OnHashComputeClick);

        g_btn_hash_copy = new Fl_Button(180, 220, 120, 30, "Copy Hash");
        g_btn_hash_copy->callback(OnHashCopyClick);

        g_btn_hash_clear = new Fl_Button(310, 220, 100, 30, "Clear");
        g_btn_hash_clear->callback(OnHashClearClick);

    hash_group->end();
    hash_group->hide();

    g_main_tabs->end();

    // ===============================================================
    // Shared Components: Console and Progress Bar (Outside Tabs)
    // ===============================================================
    g_console = new JohnnyConsole(10, 270, 600, 220);
    g_text_buffer = new Fl_Text_Buffer();
    g_console->buffer(g_text_buffer);
    g_console->color(fl_rgb_color(39, 40, 34));     // Monokai Background
    g_console->textcolor(fl_rgb_color(166, 226, 46)); // Monokai Green
    g_console->textfont(FL_COURIER);
    g_text_buffer->text("Status messages will be displayed here...\n");

    g_progress_bar = new Fl_Progress(10, 505, 600, 25, "0%");
    g_progress_bar->minimum(0);
    g_progress_bar->maximum(100);
    g_progress_bar->color(fl_rgb_color(230, 230, 230));
    g_progress_bar->selection_color(fl_rgb_color(70, 150, 220));

    win->end();
    win->position((Fl::w() - win->w()) / 2, (Fl::h() - win->h()) / 2);
    win->show(argc, argv);

    return Fl::run();
}