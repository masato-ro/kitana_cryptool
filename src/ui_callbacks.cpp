#include "ui_callbacks.h"
#include "aescrypt.h"
#include "keygen.h"
#include "passwdgen.h"
#include "hashutil.h"

#include <FL/Fl.H>
#include <FL/Fl_Native_File_Chooser.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/fl_ask.H>
#include <FL/Fl_Progress.H>
#include <FL/Fl_Value_Slider.H>
#include <FL/Fl_Tabs.H>
#include <FL/Fl_Help_View.H>
#include <FL/Fl_PNG_Image.H>
#include <FL/Fl_Shared_Image.H>
#include <FL/Fl_Box.H>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/crypto.h>

#include <thread>
#include <mutex>
#include <cstring>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

#ifndef _WIN32
#include <mach-o/dyld.h> // Core fix: macOS navigation required
#include <limits.h>
#include <string>

// macOS only: dynamically compute absolute path inside Resources
std::string get_mac_asset_path(const std::string& relative_asset) {
    char path[PATH_MAX];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0) {
        std::string exe_path(path);
        size_t last_slash = exe_path.find_last_of("/");
        if (last_slash != std::string::npos) {
            // remove executable name to get .../Kitana_Cryptool.app/Contents/MacOS
            std::string base_dir = exe_path.substr(0, last_slash);
            // align precisely to Resources: .../Contents/MacOS/../Resources/relative_asset
            return base_dir + "/../Resources/" + relative_asset;
        }
    }
    return relative_asset; // fallback
}
#endif

// Static temporary string for OpenSSH public key to be copied to clipboard
static std::string s_last_ssh_pubkey;

// Console right-click defense
int JohnnyConsole::handle(const int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_BUTTON3) return 1;
    return Fl_Text_Display::handle(event);
}

// ===================================================================
// Asynchronous Thread-Safe UI Update Pipeline
// ===================================================================
struct UIUpdateData {
    std::string msg;
    int progress_val;
    bool is_log;
};

void update_ui_callback(void* data) {
    auto* ui_data = static_cast<UIUpdateData*>(data);

    if (ui_data->is_log) {
        std::lock_guard<std::mutex> lock(g_console_mutex);
        g_text_buffer->append(ui_data->msg.c_str());
        g_console->insert_position(g_text_buffer->length());
        g_console->show_insert_position();
    } else {
        g_progress_bar->value(static_cast<float>(ui_data->progress_val));
        static char label_buf[16];
        snprintf(label_buf, sizeof(label_buf), "%d%%", ui_data->progress_val);
        g_progress_bar->label(label_buf);
    }

    delete ui_data;
}

void log_to_console(const std::string& text) {
    auto* data = new UIUpdateData{text + "\n", 0, true};
    Fl::awake(update_ui_callback, data);
}

void set_progress(int percent) {
    // Use Fl::awake to push the update request to the main thread event loop
    Fl::awake([](void* data) {
        auto p = static_cast<int>(reinterpret_cast<intptr_t>(data));
        g_progress_bar->value(static_cast<float>(p));

        char buf[16];
        snprintf(buf, sizeof(buf), "%d%%", p);
        g_progress_bar->copy_label(buf);

        // Force FLTK to redraw the progress bar
        g_progress_bar->redraw();
    }, reinterpret_cast<void*>(static_cast<intptr_t>(percent)));
}

void showLicenseDialog(const char* title, const char* filePath) {
    // 1. Read the license text file content
    std::ifstream file(filePath);
    std::string fileContent;

    if (file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();
        fileContent = ss.str();
    } else {
        fileContent = "Unable to load license file.\nPlease verify if the path exists: " + std::string(filePath);
    }

    // 2. Create a standalone popup window (Width 650, Height 400)
    auto* lic_win = new Fl_Window(650, 400, title);
    lic_win->set_modal(); // Lock the window
    lic_win->begin();

    // 3. Create a text viewer to display the terms (15px margin on all sides)
    auto* view = new Fl_Help_View(15, 15, 620, 320);
    view->textfont(FL_COURIER); // Use monospace font for better readability
    view->textsize(12);

    // 4. If it's plain text, wrap it in <pre> tags to preserve formatting
    const std::string html_wrapper = "<html><body><pre>" + fileContent + "</pre></body></html>";
    view->value(html_wrapper.c_str());

    // 5. Bottom close button
    auto* btn_close = new Fl_Button(275, 350, 100, 30, "Close");
    btn_close->labelfont(FL_FREE_FONT);
    btn_close->callback([](Fl_Widget* w, void* win_ptr) {
        auto* win = static_cast<Fl_Window*>(win_ptr);
        win->hide();
        delete win; // Self-destruct, safe release
    }, lic_win);

    lic_win->end();

    // 6. Center the window
    lic_win->position((Fl::w() - lic_win->w()) / 2, (Fl::h() - lic_win->h()) / 2);
    lic_win->show();
}

// ===================================================================
// Menu Bar Callbacks
// ===================================================================
void MenuBarCallback(Fl_Widget* w, void* data) {
    const char* selection = static_cast<const char*>(data);
    if (strcmp(selection, "Exit") == 0) {
        exit(0);
    }
    if (strcmp(selection, "Tab_AES") == 0) {
        g_main_tabs->value(g_main_tabs->child(0));
    }
    if (strcmp(selection, "Tab_KeyGen") == 0) {
        g_main_tabs->value(g_main_tabs->child(1));
    }
    if (strcmp(selection, "Tab_PasswdGen") == 0) {
        g_main_tabs->value(g_main_tabs->child(2));
    }
    if (strcmp(selection, "Tab_Hash") == 0) {
        g_main_tabs->value(g_main_tabs->child(3));
    }
    if (strcmp(selection, "About") == 0) {
        // 1. Adjust window height to 380 to leave room for the image
        auto* dialog = new Fl_Window(460, 380, "About");
        dialog->set_modal();
        dialog->begin();

        // 2. HTML content
        char aboutHtml[2048];
        snprintf(aboutHtml, sizeof(aboutHtml),
            R"(<html><body><font face='Microsoft JhengHei, Segoe UI' size='3'>)"
            R"(<b>Kitana Cryptool - Crypto Engine Matrix</b> (Version %s)<br>)"
            R"(This project is developed using FLTK and OpenSSL.<br><br>)"
            R"(<b>Used libraries and licenses:</b><br>)"
            R"(FLTK: 1.4.0 (License: LGPL)<br>)"
            R"(OpenSSL: %s (License: Apache License 2.0)<br>)"
            R"(Using OpenSSL dynamic link library (DLL) version.<br><br>)"
            R"(This software itself is licensed under the <b>MIT License</b>.<br>)"
            R"(<i>See the LICENSE file in the project for detailed licensing terms.</i>)"
            R"(</font></body></html>)",
            APP_VERSION,
            OpenSSL_version(OPENSSL_VERSION)
        );

        auto* aboutLabel = new Fl_Help_View(20, 20, 420, 180);
        aboutLabel->box(FL_NO_BOX);
        aboutLabel->color(dialog->color());
        aboutLabel->value(aboutHtml);

        // 3. Layout fix: Move image down to 200 to avoid collision with text above
        auto* iconBox = new Fl_Box(198, 200, 64, 64);
        iconBox->box(FL_FLAT_BOX);
        iconBox->color(dialog->color());

        fl_register_images();

        static Fl_Image* app_icon = nullptr;

        if (!app_icon) {
        #ifdef _WIN32
            // Windows platform: use Win32 resource loading for embedded image
            HMODULE hMod = GetModuleHandle(nullptr);
            // Ensure resource.rc defines 101 RCDATA "app.png"
            HRSRC hRes = FindResource(hMod, MAKEINTRESOURCE(101), RT_RCDATA);
            if (hRes) {
                HGLOBAL hLoad = LoadResource(hMod, hRes);
                if (hLoad) {
                    const auto* pngData = static_cast<const unsigned char*>(LockResource(hLoad));
                    const DWORD size = SizeofResource(hMod, hRes);

                    if (pngData && size > 0) {
                        app_icon = new Fl_PNG_Image(nullptr, pngData, static_cast<int>(size));
                    }
                }
            }
        #else
            // macOS: use asset path lookup to load the image
            std::string final_png_path = get_mac_asset_path("app.png");
            app_icon = new Fl_PNG_Image(final_png_path.c_str());

            // Fallback safety in case running the standalone binary from terminal
            if (!app_icon || app_icon->w() == 0) {
                if (app_icon) delete app_icon;
                app_icon = new Fl_PNG_Image("app.png");
            }
        #endif
            // Cross-platform safe handling and scaling routine
            if (app_icon) {
                if (app_icon->w() == 0) { // decoding failed (width is 0)
                    delete app_icon;
                    app_icon = nullptr;
                } else {
                    // crop/scale the loaded source image to fit the panel's 64x64 size precisely
                    Fl_Image* temp = app_icon->copy(64, 64);
                    delete app_icon;
                    app_icon = temp;
                }
            }
        }

        // Final icon render mount
        if (app_icon) {
            iconBox->image(app_icon);
        } else {
            iconBox->label("Load Fail");
        }

        // 4. Button layout fix: Move Y-axis to 280 to clear the image bottom (264)
        constexpr int btn_w = 120;
        constexpr int btn_h = 28;
        constexpr int btn_y = 280;
        constexpr int start_x = 25;
        constexpr int gap = 25;

        auto* licenseMITButton    = new Fl_Button(start_x,                     btn_y, btn_w, btn_h, "MIT License");
        auto* licenseLGPLButton   = new Fl_Button(start_x + (btn_w + gap),     btn_y, btn_w, btn_h, "LGPL License");
        auto* licenseApacheButton = new Fl_Button(start_x + (btn_w + gap) * 2, btn_y, btn_w, btn_h, "Apache License");

        licenseMITButton->labelfont(FL_FREE_FONT);
        licenseLGPLButton->labelfont(FL_FREE_FONT);
        licenseApacheButton->labelfont(FL_FREE_FONT);

        // 5. Core Wiring: callbacks for license buttons (macOS absolute path handling)
        licenseMITButton->callback([](Fl_Widget*, void*) {
        #ifdef _WIN32
            // Windows retains relative path because the .exe working directory is adjacent.
            showLicenseDialog("MIT License", "licenses/mit.txt");
        #else
            // macOS: compute absolute path to Resources/licenses/mit.txt.
            std::string abs_path = get_mac_asset_path("licenses/mit.txt");
            showLicenseDialog("MIT License", abs_path.c_str());
        #endif
        });

        licenseLGPLButton->callback([](Fl_Widget*, void*) {
        #ifdef _WIN32
            showLicenseDialog("LGPL License", "licenses/lgpl-3.0.txt");
        #else
            // macOS: compute absolute path to Resources/licenses/lgpl-3.0.txt.
            std::string abs_path = get_mac_asset_path("licenses/lgpl-3.0.txt");
            showLicenseDialog("LGPL License", abs_path.c_str());
        #endif
        });
        
        licenseApacheButton->callback([](Fl_Widget*, void*) {
        #ifdef _WIN32
            showLicenseDialog("Apache License", "licenses/apache-2.0.txt");
        #else
            // macOS: compute absolute path to Resources/licenses/apache-2.0.txt.
            std::string abs_path = get_mac_asset_path("licenses/apache-2.0.txt");
            showLicenseDialog("Apache License", abs_path.c_str());
        #endif
        });

        auto* btn_ok = new Fl_Button(180, 330, 100, 30, "OK");

        btn_ok->callback([](Fl_Widget* w, void* win_ptr) {
            auto* win = static_cast<Fl_Window*>(win_ptr);
            win->hide();
            delete win;
        }, dialog);

        dialog->end();
        dialog->position((Fl::w() - dialog->w()) / 2, (Fl::h() - dialog->h()) / 2);
        dialog->show();
    }
}

// ===================================================================
// AES Page Callbacks
// ===================================================================
void OnBrowseInputClick(Fl_Widget*, void*) {
    Fl_Native_File_Chooser file_chooser;
    file_chooser.title("Please select input file");
    file_chooser.type(Fl_Native_File_Chooser::BROWSE_FILE);
    if (file_chooser.show() == 0) g_input_file->value(file_chooser.filename());
}

void OnBrowseOutputClick(Fl_Widget*, void*) {
    Fl_Native_File_Chooser file_chooser;
    file_chooser.title("Please specify output path and filename");
    file_chooser.type(Fl_Native_File_Chooser::BROWSE_SAVE_FILE);
    if (file_chooser.show() == 0) g_output_file->value(file_chooser.filename());
}

void OnStartClick(Fl_Widget*, void*) {
    const std::string inFile  = g_input_file->value();
    const std::string outFile = g_output_file->value();
    const std::string password = g_password_input->value();
    const int mode = g_mode_choice->value();

    if (inFile.empty() || outFile.empty() || password.empty()) {
        g_text_buffer->text("[Error] Fields cannot be empty! Please configure input/output files and password.\n");
        return;
    }

    g_btn_start->deactivate();
    g_text_buffer->text("");

    std::thread worker([inFile, outFile, password, mode]() {
        log_to_console("Core Matrix Starting...");
        set_progress(0);

        auto progress_handler = [](const int percent) {
            set_progress(percent);
        };

        if (mode == 0) {
            log_to_console("Performing PBKDF2 (100k iterations) key derivation and AES-256-CBC encryption...");
            if (bool success = AESCrypt::encryptFile(inFile, outFile, password, progress_handler); success) {
                log_to_console("[Success] File has been successfully encrypted!");
                set_progress(100);
            } else {
                log_to_console("[Error] Encryption failed! Please check permissions or disk space.");
            }
        }
        else {
            log_to_console("Reading salt and verifying key... Performing decryption...");
            if (bool success = AESCrypt::decryptFile(inFile, outFile, password, progress_handler); success) {
                log_to_console("[Success] Password correct! File has been safely decrypted.");
                set_progress(100);
            } else {
                log_to_console("[Failed] Key mismatch! Incorrect password or corrupted file.");
                set_progress(0);
            }
        }

        Fl::awake([](void*) { g_btn_start->activate(); }, nullptr);
    });

    worker.detach();
}

void OnClearClick(Fl_Widget*, void*) {
    g_input_file->value("");
    g_output_file->value("");
    g_password_input->value("");
    g_text_buffer->text(">_ Status cleared. System ready.\n");
    set_progress(0);
}

// ===================================================================
// KeyGen Page Callbacks
// ===================================================================
void OnBrowsePrivateClick(Fl_Widget*, void*) {
    Fl_Native_File_Chooser file_chooser;
    file_chooser.title("Specify RSA Private Key Storage Location");
    file_chooser.type(Fl_Native_File_Chooser::BROWSE_SAVE_FILE);
    file_chooser.filter("Private Key (*.pem)\tAll Files (*.*)");
    file_chooser.preset_file("id_rsa");
    if (file_chooser.show() == 0) g_priv_key_path->value(file_chooser.filename());
}

void OnBrowsePublicClick(Fl_Widget*, void*) {
    Fl_Native_File_Chooser file_chooser;
    file_chooser.title("Specify RSA Public Key Storage Location");
    file_chooser.type(Fl_Native_File_Chooser::BROWSE_SAVE_FILE);
    file_chooser.filter("Public Key (*.pub)\tAll Files (*.*)");
    file_chooser.preset_file("id_rsa.pub");
    if (file_chooser.show() == 0) g_pub_key_path->value(file_chooser.filename());
}

void OnSshCheckClick(Fl_Widget* w, void*) {
    if (const auto* chk = dynamic_cast<Fl_Check_Button*>(w); chk && chk->value()) {
        g_ssh_comment_input->activate();
    } else {
        g_ssh_comment_input->deactivate();
    }
}

void OnGenerateKeyClick(Fl_Widget*, void*) {
    const std::string privatePath = g_priv_key_path->value();
    const std::string publicPath  = g_pub_key_path->value();
    const bool generateSshKey = g_ssh_key_check->value() != 0;
    const std::string comment  = g_ssh_comment_input->value();

    if (privatePath.empty() || publicPath.empty()) {
        g_text_buffer->text("[Error] Please specify output paths for both private and public keys!\n");
        return;
    }

    g_btn_generate_key->deactivate();
    g_text_buffer->text("");

    std::thread worker([privatePath, publicPath, generateSshKey, comment]() {
        log_to_console("Starting OpenSSL Asymmetric Cryptography Matrix...");
        set_progress(30);

        int bits = 2048;
        const int choice_idx = g_keygen_bits->value();
        if (choice_idx == 0) bits = 1024;
        else if (choice_idx == 2) bits = 4096;

        if (bool success = KeyGen::generateRSAKeyPair(bits, privatePath, publicPath); success) {
            std::string report = "[Success] RSA Key Pair generated successfully!\n Private Key: " + privatePath + "\nPublic Key: " + publicPath + "\n";

            if (generateSshKey) {
                if (EVP_PKEY* pkey = KeyGen::loadPrivateKeyFromFile(privatePath); pkey) {
                    s_last_ssh_pubkey = KeyGen::generateOpenSSHPublicKey(pkey, comment);
                    report += "\nOpenSSH public key format generated. Click Copy to use.";
                    EVP_PKEY_free(pkey);
                } else {
                    report += "Note: Keys generated, but failed to load private key for OpenSSH conversion.\n";
                }
            }
            log_to_console(report);
            set_progress(100);
        } else {
            log_to_console("[Failed] OpenSSL key generation failed. Check file paths or folder permissions!");
            set_progress(0);
        }

        Fl::awake([](void*) { g_btn_generate_key->activate(); }, nullptr);
    });

    worker.detach();
}

void OnCopySSHClick(Fl_Widget*, void*) {
    if (s_last_ssh_pubkey.empty()) {
        fl_message("Copy failed! No OpenSSH key string available.");
        return;
    }
    Fl::copy(s_last_ssh_pubkey.c_str(), static_cast<int>(s_last_ssh_pubkey.length()), 1);
    fl_message("[Success] OpenSSH public key copied to clipboard!");
}

void OnKeyGenClearClick(Fl_Widget*, void*) {
    g_priv_key_path->value("");
    g_pub_key_path->value("");
    g_ssh_comment_input->value("");
    g_ssh_comment_input->deactivate();
    g_ssh_key_check->value(0);
    g_text_buffer->text("The result of the generated key will be displayed here.\n");
    s_last_ssh_pubkey = "";
    set_progress(0);
}

// ===================================================================
// PasswdGen Page Callbacks
// ===================================================================
void OnGeneratePasswordClick(Fl_Widget*, void*) {
    const int length = static_cast<int>(g_passwd_len_slider->value());
    const bool useUpper = g_chk_upper->value();
    const bool useLower = g_chk_lower->value();
    const bool useDigits = g_chk_digits->value();
    const bool useSymbols = g_chk_symbols->value();

    if (!useUpper && !useLower && !useDigits && !useSymbols) {
        g_text_buffer->text("[Error] Please select at least one character type!\n");
        g_generated_passwd_input->value("");
        g_passwd_strength->value(0);
        g_passwd_strength->label("");
        g_passwd_strength->redraw();
        return;
    }

    std::string password = PasswdGen::generatePassword(length, useUpper, useLower, useDigits, useSymbols);
    g_generated_passwd_input->value(password.c_str());

    int score = PasswdGen::getPasswordStrengthScoreSimple(password);

    float visual_progress = (static_cast<float>(score) / 4.0f) * 100.0f;
    if (visual_progress == 0.0f && !password.empty()) {
        visual_progress = 10.0f;
    }

    g_passwd_strength->value(visual_progress);

    switch(score) {
        case 0:
            g_passwd_strength->selection_color(FL_RED);
            g_passwd_strength->label("Very Weak");
            break;
        case 1:
            g_passwd_strength->selection_color(FL_YELLOW);
            g_passwd_strength->label("Weak");
            break;
        case 2:
            g_passwd_strength->selection_color(FL_BLUE);
            g_passwd_strength->label("Good");
            break;
        case 3:
        case 4:
            g_passwd_strength->selection_color(FL_GREEN);
            g_passwd_strength->label("Strong");
            break;
        default:
            g_passwd_strength->selection_color(FL_GRAY);
            g_passwd_strength->label("");
            break;
    }

    g_passwd_strength->redraw();

    log_to_console("Password generated successfully!");
}

void OnCopyPasswordClick(Fl_Widget*, void*) {
    const char* password = g_generated_passwd_input->value();
    if (password && *password) {
        Fl::copy(password, static_cast<int>(strlen(password)), 1);
        fl_message("[Success]  Password copied to clipboard!");
        log_to_console("Password copied to clipboard.");
    } else {
        fl_message("[Error] No password to copy.");
        log_to_console("Copy failed: No password available.");
    }
}

void OnPasswdClearClick(Fl_Widget*, void*) {
    g_generated_passwd_input->value("");
    g_passwd_strength->value(0);
    g_passwd_strength->label("");
    g_passwd_strength->redraw();
    g_chk_upper->value(1);
    g_chk_lower->value(1);
    g_chk_digits->value(1);
    g_chk_symbols->value(1);
    g_passwd_len_slider->value(16);
    log_to_console("Password generator fields cleared.");
}

// ===================================================================
// Hash Matrix Callbacks
// ===================================================================
void OnHashModeChangeClick(Fl_Widget*, void*) {
    if (g_hash_mode_choice->value() == 0) {
        g_btn_hash_browse->activate();
    } else {
        g_btn_hash_browse->deactivate();
    }
    g_hash_input_source->value("");
    g_hash_result_input->value("");
    g_hash_input_source->redraw();
}

void OnHashBrowseClick(Fl_Widget*, void*) {
    Fl_Native_File_Chooser file_chooser;
    file_chooser.title("Select file to calculate hash");
    file_chooser.type(Fl_Native_File_Chooser::BROWSE_FILE);
    if (file_chooser.show() == 0) {
        g_hash_input_source->value(file_chooser.filename());
    }
}

void OnHashComputeClick(Fl_Widget*, void*) {
    g_progress_bar->value(0);
    g_progress_bar->copy_label("0%");
    g_progress_bar->redraw();
    const std::string inputData = g_hash_input_source->value();
    const int mode = g_hash_mode_choice->value();
    const int algIdx = g_hash_alg_choice->value();

    if (inputData.empty()) {
        g_text_buffer->text("[Error] Please enter text or select a file path!\n");
        g_hash_result_input->value("");
        return;
    }

    HashAlgorithm algorithm = HashAlgorithm::MD5;
    if (algIdx == 1) algorithm = HashAlgorithm::SHA1;
    else if (algIdx == 2) algorithm = HashAlgorithm::SHA256;
    else if (algIdx == 3) algorithm = HashAlgorithm::SHA3_256;

    std::string algName = hashAlgorithmToString(algorithm);

    g_btn_hash_compute->deactivate();
    g_hash_result_input->value("");
    g_text_buffer->text("");

    std::thread worker([inputData, mode, algorithm, algName]() {
        log_to_console("Starting OpenSSL Hash Engine [" + algName + "]...");
        set_progress(0);

        std::string resultHash;

        if (mode == 0) {
            log_to_console("Streaming file and calculating hash...");
            auto progress_handler = [](int percent) {
                set_progress(percent);
            };
            resultHash = HashUtil::computeHashFromFile(inputData, algorithm, progress_handler);
        }
        else {
            log_to_console("Calculating hash from text...");
            resultHash = HashUtil::computeHashFromText(inputData, algorithm);
            set_progress(100);
        }

        if (!resultHash.empty()) {
            log_to_console("Hash calculation complete: " + algName);

            struct LambdaData { std::string hash; };
            auto* outData = new LambdaData{resultHash};

            Fl::awake([](void* d) {
                auto* p = static_cast<LambdaData*>(d);
                g_hash_result_input->value(p->hash.c_str());
                delete p;
            }, outData);
        }
        else {
            log_to_console("[Error] Hash calculation failed! Check file path or permissions.");
            set_progress(0);
        }

        Fl::awake([](void*) { g_btn_hash_compute->activate(); }, nullptr);
    });

    worker.detach();
}

void OnHashCompareFileClick(Fl_Widget*, void*) {
    // Check if local hash is computed
    const std::string computedHash = g_hash_result_input->value();
    if (computedHash.empty()) {
        fl_message("Notice: Please select a file and click [Compute Hash] first!");
        return;
    }

    // Open file chooser for checksum files
    Fl_Native_File_Chooser file_chooser;
    file_chooser.title("Select Checksum File (*.sha256; *.md5; *.txt)");
    file_chooser.type(Fl_Native_File_Chooser::BROWSE_FILE);
    file_chooser.filter("Checksum Files\t*.{sha256,sha1,md5,txt}\nAll Files\t*");
    if (file_chooser.show() != 0) return;

    std::string parsedHash;
    if (HashUtil::compareHashWithFile(computedHash, file_chooser.filename(), parsedHash)) {
        log_to_console("[Success] Hashes match! The file is intact.");
        fl_message("Verification Successful: Hashes match!");
    } else {
        if (parsedHash.empty()) {
            log_to_console("[Failed] Incompatible checksum file format.");
            fl_message("Error: Could not parse a valid hash from the file!");
        } else {
            log_to_console("[Warning] Hash mismatch! The file may be corrupted or modified.");
            fl_message("Alert: Hash mismatch detected!");
        }
    }
    log_to_console("--------------------------------------------------");
    log_to_console("Local Hash: " + computedHash);
    log_to_console("File Hash : " + parsedHash);
    log_to_console("--------------------------------------------------");
}

void OnHashCopyClick(Fl_Widget*, void*) {
    const char* hashVal = g_hash_result_input->value();
    if (hashVal && *hashVal) {
        Fl::copy(hashVal, static_cast<int>(strlen(hashVal)), 1);
        fl_message("[Success] Hash value copied to clipboard!");
        log_to_console("Hash value copied to clipboard.");
    } else {
        fl_message("[Error] No hash value to copy.");
    }
}

void OnHashClearClick(Fl_Widget*, void*) {
    g_hash_input_source->value("");
    g_hash_result_input->value("");
    g_text_buffer->text("Hash matrix reset. System ready.\n");
    set_progress(0);
}