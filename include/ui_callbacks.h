#ifndef UI_CALLBACKS_H
#define UI_CALLBACKS_H

#include <string>
#include <mutex>

#include <FL/Fl_Widget.H>
#include <FL/Fl_Text_Display.H>

// Forward declarations for FLTK components
class Fl_Choice;
class Fl_Input;
class Fl_Secret_Input;
class Fl_Button;
class Fl_Check_Button;
class Fl_Progress;
class Fl_Text_Buffer;
class Fl_Value_Slider;
class Fl_Tabs;

// ===================================================================
// Global Application Info
// ===================================================================
constexpr const char* APP_VERSION = "0.1";

// ===================================================================
// OCD Defense: Custom subclass to override right-click menu
// ===================================================================
class JohnnyConsole : public Fl_Text_Display {
public:
    JohnnyConsole(int X, int Y, int W, int H, const char* L = nullptr)
        : Fl_Text_Display(X, Y, W, H, L) {}
    int handle(int event) override;
};

// ===================================================================
// Global variables declared in main.cpp
// ===================================================================
// --- Tab Framework ---
extern Fl_Tabs* g_main_tabs;

// --- Tab 1: AES ---
extern Fl_Choice* g_mode_choice;
extern Fl_Input* g_input_file;
extern Fl_Input* g_output_file;
extern Fl_Secret_Input* g_password_input;
extern Fl_Button* g_btn_start;
extern Fl_Button* g_btn_clear;

// --- Tab 2: KeyGen ---
extern Fl_Choice* g_keygen_bits;
extern Fl_Input* g_priv_key_path;
extern Fl_Input* g_pub_key_path;
extern Fl_Check_Button* g_ssh_key_check;
extern Fl_Input* g_ssh_comment_input;
extern Fl_Button* g_btn_generate_key;
extern Fl_Button* g_btn_copy_ssh;
extern Fl_Button* g_btn_keygen_clear;

// --- Tab 3: PasswdGen ---
extern Fl_Value_Slider* g_passwd_len_slider;
extern Fl_Check_Button* g_chk_upper;
extern Fl_Check_Button* g_chk_lower;
extern Fl_Check_Button* g_chk_digits;
extern Fl_Check_Button* g_chk_symbols;
extern Fl_Input* g_generated_passwd_input;
extern Fl_Button* g_btn_generate_passwd;
extern Fl_Button* g_btn_copy_passwd;
extern Fl_Button* g_btn_passwd_clear; // 🎯 新增清除按鈕指標
extern Fl_Progress* g_passwd_strength;

// --- Tab 4: Hash Matrix ---
extern Fl_Choice* g_hash_mode_choice;
extern Fl_Choice* g_hash_alg_choice;
extern Fl_Input* g_hash_input_source;
extern Fl_Button* g_btn_hash_browse;
extern Fl_Input* g_hash_result_input;
extern Fl_Button* g_btn_hash_compute;
extern Fl_Button* g_btn_hash_copy;
extern Fl_Button* g_btn_hash_clear;
extern Fl_Button* g_btn_hash_compare;

// --- Shared Components ---
extern Fl_Progress* g_progress_bar;
extern Fl_Text_Display* g_console;
extern Fl_Text_Buffer* g_text_buffer;
extern std::mutex g_console_mutex;

// ===================================================================
// Callback Function Declarations
// ===================================================================

// --- Menu Callback ---
void MenuBarCallback(Fl_Widget*, void*);

// --- AES Callbacks ---
void OnBrowseInputClick(Fl_Widget*, void*);
void OnBrowseOutputClick(Fl_Widget*, void*);
void OnStartClick(Fl_Widget*, void*);
void OnClearClick(Fl_Widget*, void*);

// --- KeyGen Callbacks ---
void OnBrowsePrivateClick(Fl_Widget*, void*);
void OnBrowsePublicClick(Fl_Widget*, void*);
void OnSshCheckClick(Fl_Widget*, void*);
void OnGenerateKeyClick(Fl_Widget*, void*);
void OnCopySSHClick(Fl_Widget*, void*);
void OnKeyGenClearClick(Fl_Widget*, void*);

// --- PasswdGen Callbacks ---
void OnGeneratePasswordClick(Fl_Widget*, void*);
void OnCopyPasswordClick(Fl_Widget*, void*);
void OnPasswdClearClick(Fl_Widget*, void*); // 🎯 宣告新的回呼函式

// --- Hash Matrix Callback ---
void OnHashModeChangeClick(Fl_Widget*, void*);
void OnHashBrowseClick(Fl_Widget*, void*);
void OnHashComputeClick(Fl_Widget*, void*);
void OnHashCopyClick(Fl_Widget*, void*);
void OnHashClearClick(Fl_Widget*, void*);
void OnHashCompareFileClick(Fl_Widget*, void*);

// --- UI Update Helper Functions ---
void log_to_console(const std::string& text);
void set_progress(int percent);

#endif // UI_CALLBACKS_H