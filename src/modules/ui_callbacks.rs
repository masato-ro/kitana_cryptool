use fltk::{app, dialog, prelude::*};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

pub fn setup_aes_callbacks(
    btn_browse_in: &mut fltk::button::Button,
    btn_browse_out: &mut fltk::button::Button,
    btn_start: &mut fltk::button::Button,
    btn_stop: &mut fltk::button::Button,
    btn_clear: &mut fltk::button::Button,
    input_file: fltk::input::Input,
    output_file: fltk::input::Input,
    password_input: fltk::input::SecretInput,
    mode_choice: fltk::menu::Choice,
    text_buffer: fltk::text::TextBuffer,
    progress: fltk::misc::Progress,
) {
    btn_browse_in.set_callback({
        let mut inp = input_file.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseFile);
            dialog.set_title("Select Input File");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                inp.set_value(&path_str);
            }
        }
    });

    btn_browse_out.set_callback({
        let mut outp = output_file.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseSaveFile);
            dialog.set_title("Select Output File");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                outp.set_value(&path_str);
            }
        }
    });

    btn_stop.deactivate(); // 預設停用 Stop 按鈕
    let cancel_flag = Arc::new(AtomicBool::new(false));

    btn_stop.set_callback({
        let flag = cancel_flag.clone();
        move |_| {
            flag.store(true, Ordering::Relaxed);
        }
    });

    btn_start.set_callback({
        let mode = mode_choice.clone();
        let inp = input_file.clone();
        let outp = output_file.clone();
        let pwd = password_input.clone();
        let mut buf = text_buffer.clone();
        let mut prog = progress.clone();
        let flag = cancel_flag.clone();
        let mut b_start = btn_start.clone();
        let mut b_stop = btn_stop.clone();
        move |_| {
            let is_encrypt = mode.value() == 0;
            let inp_val = inp.value();
            let outp_val = outp.value();
            let pwd_val = pwd.value();

            if inp_val.is_empty() || outp_val.is_empty() || pwd_val.is_empty() {
                dialog::alert_default("Please fill in all fields (Input, Output, Password).");
                return;
            }
            
            let action = if is_encrypt { "Encrypting" } else { "Decrypting" };
            buf.append(&format!("{} file: {}...\n", action, inp_val));
            
            prog.set_value(0.0);
            prog.set_label("0%");

            // 重設取消旗標並切換按鈕狀態
            flag.store(false, Ordering::Relaxed);
            b_start.deactivate();
            b_stop.activate();

            let buf_clone = buf.clone();
            let prog_clone = prog.clone();
            let flag_clone = flag.clone();
            let b_start_clone = b_start.clone();
            let b_stop_clone = b_stop.clone();

            std::thread::spawn(move || {
                let callback = Box::new(move |p: u32| {
                    app::awake_callback({
                        let mut prg = prog_clone.clone();
                        move || {
                            prg.set_value(p as f64);
                            prg.set_label(&format!("{}%", p));
                        }
                    });
                });

                let res = if is_encrypt {
                    crate::modules::aescrypt::AESCrypt::encrypt_file_with_progress(&inp_val, &outp_val, &pwd_val, Some(callback), Some(flag_clone))
                } else {
                    crate::modules::aescrypt::AESCrypt::decrypt_file_with_progress(&inp_val, &outp_val, &pwd_val, Some(callback), Some(flag_clone))
                };

                app::awake_callback({
                    let mut b = buf_clone.clone();
                    let mut start_btn = b_start_clone.clone();
                    let mut stop_btn = b_stop_clone.clone();
                    move || {
                        start_btn.activate();
                        stop_btn.deactivate();

                        match &res {
                            Ok(_) => b.append("Operation completed successfully.\n\n"),
                            Err(e) => b.append(&format!("Error: {}\n\n", e)),
                        }
                    }
                });
            });
        }
    });

    btn_clear.set_callback({
        let mut inp = input_file.clone();
        let mut outp = output_file.clone();
        let mut pwd = password_input.clone();
        move |_| {
            inp.set_value("");
            outp.set_value("");
            pwd.set_value("");
        }
    });
}

pub fn setup_keygen_callbacks(
    btn_browse_priv: &mut fltk::button::Button,
    btn_browse_pub: &mut fltk::button::Button,
    check_ssh: &mut fltk::button::CheckButton,
    btn_generate: &mut fltk::button::Button,
    btn_copy: &mut fltk::button::Button,
    btn_clear: &mut fltk::button::Button,
    choice_bits: fltk::menu::Choice,
    input_priv: fltk::input::Input,
    input_pub: fltk::input::Input,
    input_comment: fltk::input::Input,
    text_buffer: fltk::text::TextBuffer,
    progress: fltk::misc::Progress,
) {
    // 建立一個跨執行緒共享的狀態，用來儲存最後一次產生的 OpenSSH 公鑰字串
    let shared_ssh_key = Arc::new(Mutex::new(String::new()));

    btn_browse_priv.set_callback({
        let mut inp = input_priv.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseSaveFile);
            dialog.set_title("Specify RSA Private Key Storage Location");
            dialog.set_filter("PEM Files\t*.pem\nAll Files\t*.*");
            dialog.set_preset_file("id_rsa.pem");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                inp.set_value(&path_str);
            }
        }
    });

    btn_browse_pub.set_callback({
        let mut inp = input_pub.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseSaveFile);
            dialog.set_title("Specify RSA Public Key Storage Location");
            dialog.set_filter("Public Key Files\t*.pub\nAll Files\t*.*");
            dialog.set_preset_file("id_rsa.pub");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                inp.set_value(&path_str);
            }
        }
    });

    check_ssh.set_callback({
        let mut inp_c = input_comment.clone();
        move |c| {
            if c.is_checked() {
                inp_c.activate();
            } else {
                inp_c.deactivate();
            }
        }
    });

    btn_generate.set_callback({
        let choice_bits = choice_bits.clone();
        let inp_priv = input_priv.clone();
        let inp_pub = input_pub.clone();
        let chk_ssh = check_ssh.clone();
        let inp_comment = input_comment.clone();
        let mut btn_gen = btn_generate.clone();
        let mut tb = text_buffer.clone();
        let prog = progress.clone();
        let ssh_key_store = shared_ssh_key.clone();

        move |_| {
            let priv_path = inp_priv.value();
            let pub_path = inp_pub.value();
            let gen_ssh = chk_ssh.is_checked();
            let comment = inp_comment.value();

            if priv_path.is_empty() || pub_path.is_empty() {
                dialog::alert_default("Please specify output paths for both private and public keys!");
                return;
            }

            btn_gen.deactivate();
            tb.set_text(""); // 清空畫面

            let bits = match choice_bits.value() {
                0 => 1024,
                2 => 4096,
                _ => 2048,
            };

            let tb_clone = tb.clone();
            let prog_clone = prog.clone();
            let btn_gen_clone = btn_gen.clone();
            let ssh_store_clone = ssh_key_store.clone();

            // 開啟背景執行緒進行繁重的質數計算任務
            std::thread::spawn(move || {
                app::awake_callback({
                    let mut t = tb_clone.clone();
                    let mut p = prog_clone.clone();
                    move || {
                        t.append("Starting Pure Rust Asymmetric Cryptography Matrix...\n");
                        p.set_value(30.0);
                        p.set_label("30%");
                    }
                });

                let mut report = String::new();
                let success = match crate::modules::keygen::KeyGen::generate_rsa_key_pair(bits, &priv_path, &pub_path) {
                    Ok(_) => {
                        report.push_str(&format!("[Success] RSA Key Pair generated successfully!\nPrivate Key: {}\nPublic Key: {}\n", priv_path, pub_path));
                        
                        if gen_ssh {
                            match crate::modules::keygen::KeyGen::load_private_key_from_file(&priv_path) {
                                Ok(pkey) => {
                                    let ssh_pub = crate::modules::keygen::KeyGen::generate_openssh_public_key(&pkey, &comment);
                                    if let Ok(mut store) = ssh_store_clone.lock() {
                                        *store = ssh_pub;
                                    }
                                    report.push_str("\nOpenSSH public key format generated. Click Copy to use.\n");
                                }
                                Err(_) => {
                                    report.push_str("Note: Keys generated, but failed to load private key for OpenSSH conversion.\n");
                                }
                            }
                        }
                        true
                    }
                    Err(_) => {
                        report.push_str("[Failed] Key generation failed. Check file paths or folder permissions!\n");
                        false
                    }
                };

                // 計算完畢後更新 UI
                app::awake_callback({
                    let mut t = tb_clone;
                    let mut p = prog_clone;
                    let mut b = btn_gen_clone;
                    move || {
                        t.append(&report);
                        if success {
                            p.set_value(100.0);
                            p.set_label("100%");
                        } else {
                            p.set_value(0.0);
                            p.set_label("0%");
                        }
                        b.activate();
                    }
                });
            });
        }
    });

    btn_copy.set_callback({
        let ssh_store = shared_ssh_key.clone();
        move |_| {
            if let Ok(store) = ssh_store.lock() {
                if store.is_empty() {
                    dialog::alert_default("Copy failed! No OpenSSH key string available.");
                } else {
                    app::copy(&store);
                    dialog::message_default("[Success] OpenSSH public key copied to clipboard!");
                }
            }
        }
    });

    btn_clear.set_callback({
        let mut inp_priv = input_priv.clone();
        let mut inp_pub = input_pub.clone();
        let mut inp_comment = input_comment.clone();
        let chk_ssh = check_ssh.clone();
        let mut tb = text_buffer.clone();
        let mut prog = progress.clone();
        let ssh_store = shared_ssh_key.clone();
        
        move |_| {
            inp_priv.set_value("");
            inp_pub.set_value("");
            inp_comment.set_value("");
            inp_comment.deactivate();
            chk_ssh.set_checked(false);
            tb.set_text("The result of the generated key will be displayed here.\n");
            prog.set_value(0.0);
            prog.set_label("0%");
            if let Ok(mut store) = ssh_store.lock() {
                *store = String::new(); // 清空剪貼簿緩存
            }
        }
    });
}

pub fn setup_passwdgen_callbacks(
    btn_generate: &mut fltk::button::Button,
    btn_copy: &mut fltk::button::Button,
    btn_clear: &mut fltk::button::Button,
    slider_len: fltk::valuator::ValueSlider,
    chk_upper: fltk::button::CheckButton,
    chk_lower: fltk::button::CheckButton,
    chk_digits: fltk::button::CheckButton,
    chk_symbols: fltk::button::CheckButton,
    input_passwd: fltk::input::Input,
    progress_strength: fltk::misc::Progress,
    text_buffer: fltk::text::TextBuffer,
    global_progress: fltk::misc::Progress,
) {
    btn_generate.set_callback({
        let slider_len = slider_len.clone();
        let chk_upper = chk_upper.clone();
        let chk_lower = chk_lower.clone();
        let chk_digits = chk_digits.clone();
        let chk_symbols = chk_symbols.clone();
        let mut input_passwd = input_passwd.clone();
        let mut progress_strength = progress_strength.clone();
        let mut text_buffer = text_buffer.clone();
        let mut global_progress = global_progress.clone();

        move |_| {
            let length = slider_len.value() as usize;
            let use_upper = chk_upper.is_checked();
            let use_lower = chk_lower.is_checked();
            let use_digits = chk_digits.is_checked();
            let use_symbols = chk_symbols.is_checked();

            if !use_upper && !use_lower && !use_digits && !use_symbols {
                text_buffer.set_text("[Error] Please select at least one character type!\n");
                input_passwd.set_value("");
                progress_strength.set_value(0.0);
                progress_strength.set_label("");
                progress_strength.redraw();
                global_progress.set_value(0.0);
                global_progress.set_label("0%");
                return;
            }

            let password = crate::modules::passwdgen::PasswdGen::generate_password(
                length, use_upper, use_lower, use_digits, use_symbols,
            );
            
            input_passwd.set_value(&password);

            let score = crate::modules::passwdgen::PasswdGen::get_password_strength_score_simple(&password);

            let mut visual_progress = (score as f64 / 4.0) * 100.0;
            if visual_progress == 0.0 && !password.is_empty() {
                visual_progress = 10.0; // 即使是最弱密碼也顯示一點點進度
            }

            progress_strength.set_value(visual_progress);

            // 根據分數調整強度條的顏色與文字
            match score {
                0 => {
                    progress_strength.set_selection_color(fltk::enums::Color::Red);
                    progress_strength.set_label("Very Weak");
                }
                1 => {
                    progress_strength.set_selection_color(fltk::enums::Color::Yellow);
                    progress_strength.set_label("Weak");
                }
                2 => {
                    progress_strength.set_selection_color(fltk::enums::Color::Blue);
                    progress_strength.set_label("Good");
                }
                3 | 4 => {
                    progress_strength.set_selection_color(fltk::enums::Color::Green);
                    progress_strength.set_label("Strong");
                }
                _ => {
                    progress_strength.set_selection_color(fltk::enums::Color::Gray0);
                    progress_strength.set_label("");
                }
            }

            progress_strength.redraw();
            text_buffer.set_text("Password generated successfully!\n");
            global_progress.set_value(100.0);
            global_progress.set_label("100%");
        }
    });

    btn_copy.set_callback({
        let input_passwd = input_passwd.clone();
        let mut text_buffer = text_buffer.clone();
        move |_| {
            let password = input_passwd.value();
            if !password.is_empty() {
                app::copy(&password);
                dialog::message_default("[Success] Password copied to clipboard!");
                text_buffer.set_text("Password copied to clipboard.\n");
            } else {
                dialog::alert_default("[Error] No password to copy.");
                text_buffer.set_text("Copy failed: No password available.\n");
            }
        }
    });

    btn_clear.set_callback({
        let mut slider_len = slider_len.clone();
        let chk_upper = chk_upper.clone();
        let chk_lower = chk_lower.clone();
        let chk_digits = chk_digits.clone();
        let chk_symbols = chk_symbols.clone();
        let mut input_passwd = input_passwd.clone();
        let mut progress_strength = progress_strength.clone();
        let mut text_buffer = text_buffer.clone();
        let mut global_progress = global_progress.clone();

        move |_| {
            input_passwd.set_value("");
            progress_strength.set_value(0.0);
            progress_strength.set_label("");
            // 恢復原本進度條的藍色預設值
            progress_strength.set_selection_color(fltk::enums::Color::from_rgb(70, 150, 220));
            progress_strength.redraw();
            
            chk_upper.set_checked(true);
            chk_lower.set_checked(true);
            chk_digits.set_checked(true);
            chk_symbols.set_checked(true);
            slider_len.set_value(16.0);

            text_buffer.set_text("Password generator fields cleared.\n");
            global_progress.set_value(0.0);
            global_progress.set_label("0%");
        }
    });
}

pub fn setup_hash_callbacks(
    mut mode_choice: fltk::menu::Choice,
    btn_browse: &mut fltk::button::Button,
    input_source: fltk::input::Input,
    alg_choice: fltk::menu::Choice,
    btn_compute: &mut fltk::button::Button,
    result_input: fltk::input::Input,
    btn_compare: &mut fltk::button::Button,
    btn_copy: &mut fltk::button::Button,
    btn_clear: &mut fltk::button::Button,
    text_buffer: fltk::text::TextBuffer,
    global_progress: fltk::misc::Progress,
) {
    mode_choice.set_callback({
        let mut btn_browse = btn_browse.clone();
        let mut input_source = input_source.clone();
        let mut result_input = result_input.clone();
        move |c| {
            if c.value() == 0 {
                btn_browse.activate();
            } else {
                btn_browse.deactivate();
            }
            input_source.set_value("");
            result_input.set_value("");
            input_source.redraw();
        }
    });

    btn_browse.set_callback({
        let mut input_source = input_source.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseFile);
            dialog.set_title("Select file to calculate hash");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                input_source.set_value(&path_str);
            }
        }
    });

    btn_compute.set_callback({
        let input_source = input_source.clone();
        let mode_choice = mode_choice.clone();
        let alg_choice = alg_choice.clone();
        let mut btn_compute = btn_compute.clone();
        let mut result_input = result_input.clone();
        let mut text_buffer = text_buffer.clone();
        let mut progress = global_progress.clone();

        move |_| {
            progress.set_value(0.0);
            progress.set_label("0%");
            progress.redraw();

            let input_data = input_source.value();
            let mode = mode_choice.value();
            let alg_idx = alg_choice.value();

            if input_data.is_empty() {
                text_buffer.set_text("[Error] Please enter text or select a file path!\n");
                result_input.set_value("");
                return;
            }

            let algorithm = match alg_idx {
                1 => crate::modules::hashutil::HashAlgorithm::SHA1,
                2 => crate::modules::hashutil::HashAlgorithm::SHA256,
                3 => crate::modules::hashutil::HashAlgorithm::SHA3_256,
                _ => crate::modules::hashutil::HashAlgorithm::MD5,
            };
            let alg_name = algorithm.to_string();

            btn_compute.deactivate();
            result_input.set_value("");
            text_buffer.set_text("");

            let mut tb_clone = text_buffer.clone();
            let mut prog_clone = progress.clone();
            let mut btn_comp_clone = btn_compute.clone();
            let mut res_inp_clone = result_input.clone();

            std::thread::spawn(move || {
                app::awake_callback({
                    let mut t = tb_clone.clone();
                    let a = alg_name.clone();
                    move || t.append(&format!("Starting Rust Hash Engine [{}]...\n", a))
                });

                let result_hash = if mode == 0 {
                    app::awake_callback({
                        let mut t = tb_clone.clone();
                        move || t.append("Streaming file and calculating hash...\n")
                    });

                    let callback = {
                        let p = prog_clone.clone();
                        move |percent: u32| {
                            app::awake_callback({
                                let mut prg = p.clone();
                                move || {
                                    prg.set_value(percent as f64);
                                    prg.set_label(&format!("{}%", percent));
                                }
                            });
                        }
                    };
                    crate::modules::hashutil::HashUtil::compute_hash_from_file(&input_data, algorithm, Some(callback))
                } else {
                    app::awake_callback({
                        let mut t = tb_clone.clone();
                        move || t.append("Calculating hash from text...\n")
                    });
                    let h = crate::modules::hashutil::HashUtil::compute_hash_from_text(&input_data, algorithm);
                    app::awake_callback({
                        let mut p = prog_clone.clone();
                        move || {
                            p.set_value(100.0);
                            p.set_label("100%");
                        }
                    });
                    h
                };

                app::awake_callback(move || {
                    if !result_hash.is_empty() {
                        tb_clone.append(&format!("Hash calculation complete: {}\n", alg_name));
                        res_inp_clone.set_value(&result_hash);
                    } else {
                        tb_clone.append("[Error] Hash calculation failed! Check file path or permissions.\n");
                        prog_clone.set_value(0.0);
                        prog_clone.set_label("0%");
                    }
                    btn_comp_clone.activate();
                });
            });
        }
    });

    btn_compare.set_callback({
        let result_input = result_input.clone();
        let mut text_buffer = text_buffer.clone();
        move |_| {
            let computed_hash = result_input.value();
            if computed_hash.is_empty() {
                dialog::message_default("Notice: Please select a file and click [Compute Hash] first!");
                return;
            }

            let mut file_chooser = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseFile);
            file_chooser.set_title("Select Checksum File (*.sha256; *.md5; *.txt)");
            file_chooser.set_filter("Checksum Files\t*.{sha256,sha1,md5,txt}\nAll Files\t*.*");
            file_chooser.show();
            let path_str = file_chooser.filename().to_string_lossy().to_string();
            if path_str.is_empty() { return; }

            let (match_found, parsed_hash) = crate::modules::hashutil::HashUtil::compare_hash_with_file(&computed_hash, &path_str);

            if match_found {
                text_buffer.append("[Success] Hashes match! The file is intact.\n");
                dialog::message_default("Verification Successful: Hashes match!");
            } else {
                if parsed_hash.is_empty() {
                    text_buffer.append("[Failed] Incompatible checksum file format.\n");
                    dialog::alert_default("Error: Could not parse a valid hash from the file!");
                } else {
                    text_buffer.append("[Warning] Hash mismatch! The file may be corrupted or modified.\n");
                    dialog::alert_default("Alert: Hash mismatch detected!");
                }
            }
            text_buffer.append("--------------------------------------------------\n");
            text_buffer.append(&format!("Local Hash: {}\n", computed_hash));
            text_buffer.append(&format!("File Hash : {}\n", parsed_hash));
            text_buffer.append("--------------------------------------------------\n");
        }
    });

    btn_copy.set_callback({
        let result_input = result_input.clone();
        let mut text_buffer = text_buffer.clone();
        move |_| {
            let hash_val = result_input.value();
            if !hash_val.is_empty() {
                app::copy(&hash_val);
                dialog::message_default("[Success] Hash value copied to clipboard!");
                text_buffer.append("Hash value copied to clipboard.\n");
            } else {
                dialog::alert_default("[Error] No hash value to copy.");
            }
        }
    });

    btn_clear.set_callback({
        let mut input_source = input_source.clone();
        let mut result_input = result_input.clone();
        let mut text_buffer = text_buffer.clone();
        let mut progress = global_progress.clone();
        move |_| {
            input_source.set_value("");
            result_input.set_value("");
            text_buffer.set_text("Hash matrix reset. System ready.\n");
            progress.set_value(0.0);
            progress.set_label("0%");
        }
    });
}

fn show_license_dialog(title: &str, content: &str) {
    let mut win = fltk::window::Window::default()
        .with_size(600, 400)
        .with_label(title);
    win.make_modal(true);
    
    let mut disp = fltk::text::TextDisplay::default().with_size(580, 340).with_pos(10, 10);
    let mut buf = fltk::text::TextBuffer::default();
    
    buf.set_text(content);
    disp.set_buffer(buf);

    let mut btn_ok = fltk::button::Button::default().with_pos(250, 360).with_size(100, 30).with_label("OK");
    btn_ok.set_callback({ let mut w = win.clone(); move |_| w.hide() });

    win.end();
    
    let (sw, sh) = app::screen_size();
    win.set_pos(((sw as i32) - win.w()) / 2, ((sh as i32) - win.h()) / 2);
    win.show();
}

pub fn show_about_dialog() {
    let mut dialog = fltk::window::Window::default()
        .with_size(460, 450)
        .with_label("About");
    dialog.make_modal(true);

    let about_html = format!(
        "<html><body><font face='Microsoft JhengHei, Segoe UI' size='3'>\
        <b>Kitana Cryptool - Crypto Engine Matrix</b> (Version {})<br>&nbsp;<br>\
        This project is developed using Rust and FLTK.<br>&nbsp;<br>\
        <b>Used libraries and licenses:</b><br>\
        fltk-rs: 1.5 (License: MIT / LGPL)<br>\
        RustCrypto (aes, cbc, cipher, md-5, pbkdf2, rsa, sha1, sha2, sha3): (License: MIT / Apache 2.0)<br>\
        rand, getrandom: (License: MIT / Apache 2.0)<br>\
        base64: (License: MIT / Apache 2.0)<br>\
        winres: (License: MIT)<br>&nbsp;<br>\
        This software itself is licensed under the <b>MIT License</b>.<br>\
        <i>See the LICENSE file in the project for detailed licensing terms.</i>\
        </font></body></html>",
        env!("CARGO_PKG_VERSION")
    );

    let mut about_label = fltk::misc::HelpView::default().with_pos(20, 20).with_size(420, 250);
    about_label.set_color(dialog.color());
    about_label.set_value(&about_html);

    let mut icon_box = fltk::frame::Frame::default().with_pos(198, 270).with_size(64, 64);
    icon_box.set_frame(fltk::enums::FrameType::FlatBox);
    icon_box.set_color(dialog.color());

    if let Ok(mut img) = fltk::image::PngImage::from_data(include_bytes!("../../app.png")) {
        img.scale(64, 64, true, true);
        icon_box.set_image(Some(img));
    } else {
        icon_box.set_label("Load Fail");
    }

    let mut btn_mit = fltk::button::Button::default().with_pos(25, 350).with_size(120, 28).with_label("MIT License");
    let mut btn_lgpl = fltk::button::Button::default().with_pos(170, 350).with_size(120, 28).with_label("LGPL License");
    let mut btn_apache = fltk::button::Button::default().with_pos(315, 350).with_size(120, 28).with_label("Apache License");

    btn_mit.set_callback(|_| show_license_dialog("MIT License", include_str!("../../licenses/mit.txt")));
    btn_lgpl.set_callback(|_| show_license_dialog("LGPL License", include_str!("../../licenses/lgpl-3.0.txt")));
    btn_apache.set_callback(|_| show_license_dialog("Apache License", include_str!("../../licenses/apache-2.0.txt")));

    let mut btn_ok = fltk::button::Button::default().with_pos(180, 400).with_size(100, 30).with_label("OK");
    btn_ok.set_callback({ let mut d = dialog.clone(); move |_| d.hide() });

    dialog.end();
    let (sw, sh) = app::screen_size();
    dialog.set_pos(((sw as i32) - dialog.w()) / 2, ((sh as i32) - dialog.h()) / 2);
    dialog.show();
}
