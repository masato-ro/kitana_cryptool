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
    password_input_sec: fltk::input::SecretInput,
    password_input_pln: fltk::input::Input,
    mode_choice: fltk::menu::Choice,
    text_buffer: fltk::text::TextBuffer,
    progress: fltk::misc::Progress,
    global_is_running: Arc<AtomicBool>,
) {
    btn_browse_in.set_callback({
        let mut inp = input_file.clone();
        let mut outp = output_file.clone();
        let mode = mode_choice.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseFile);
            dialog.set_title("Select Input File");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                inp.set_value(&path_str);
                
                // 自動推導並填寫輸出檔案路徑
                if mode.value() == 0 {
                    // Encrypt 模式：預設加上 .enc
                    outp.set_value(&format!("{}.enc", path_str));
                } else {
                    // Decrypt 模式：如果檔名以 .enc 結尾，則去掉它；否則補上 .dec
                    if path_str.to_lowercase().ends_with(".enc") {
                        outp.set_value(&path_str[..path_str.len() - 4]);
                    } else {
                        outp.set_value(&format!("{}.dec", path_str));
                    }
                }
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
        let pwd_sec = password_input_sec.clone();
        let pwd_pln = password_input_pln.clone();
        let mut buf = text_buffer.clone();
        let mut prog = progress.clone();
        let flag = cancel_flag.clone();
        let mut b_start = btn_start.clone();
        let mut b_stop = btn_stop.clone();
        let global_run = global_is_running.clone();
        move |_| {
            let is_encrypt = mode.value() == 0;
            let inp_val = inp.value();
            let outp_val = outp.value();
            let pwd_val = if pwd_sec.visible() { pwd_sec.value() } else { pwd_pln.value() };

            let inp_trimmed = inp_val.trim().trim_matches('"').to_string();
            let outp_trimmed = outp_val.trim().trim_matches('"').to_string();

            if inp_trimmed.is_empty() || outp_trimmed.is_empty() || pwd_val.is_empty() {
                dialog::alert_default("Please fill in all fields (Input, Output, Password).");
                return;
            }
            
            if std::path::Path::new(&inp_trimmed).is_dir() {
                dialog::alert_default("Directory processing is not currently supported.\nPlease select a valid input file.");
                return;
            }
            if std::path::Path::new(&outp_trimmed).is_dir() {
                dialog::alert_default("The output path is a directory.\nPlease specify a valid output file name.");
                return;
            }

            let action = if is_encrypt { "Encrypting" } else { "Decrypting" };
            buf.append(&format!("{} file: {}...\n", action, inp_trimmed));
            
            prog.set_value(0.0);
            prog.set_label("0%");

            // 重設取消旗標並切換按鈕狀態
            global_run.store(true, Ordering::Relaxed);
            flag.store(false, Ordering::Relaxed);
            b_start.deactivate();
            b_stop.activate();

            let buf_clone = buf.clone();
            let prog_clone = prog.clone();
            let flag_clone = flag.clone();
            let b_start_clone = b_start.clone();
            let b_stop_clone = b_stop.clone();
            let global_run_clone = global_run.clone();

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
                    crate::modules::aescrypt::AESCrypt::encrypt_file_with_progress(&inp_trimmed, &outp_trimmed, &pwd_val, Some(callback), Some(flag_clone))
                } else {
                    crate::modules::aescrypt::AESCrypt::decrypt_file_with_progress(&inp_trimmed, &outp_trimmed, &pwd_val, Some(callback), Some(flag_clone))
                };

                app::awake_callback({
                    let mut b = buf_clone.clone();
                    let mut start_btn = b_start_clone.clone();
                    let mut stop_btn = b_stop_clone.clone();
                    let global_run_inner = global_run_clone.clone();
                    move || {
                        global_run_inner.store(false, Ordering::Relaxed);
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
        let mut pwd_sec = password_input_sec.clone();
        let mut pwd_pln = password_input_pln.clone();
        move |_| {
            inp.set_value("");
            outp.set_value("");
            pwd_sec.set_value("");
            pwd_pln.set_value("");
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
    global_is_running: Arc<AtomicBool>,
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
        let global_run = global_is_running.clone();

        move |_| {
            let priv_path = inp_priv.value();
            let pub_path = inp_pub.value();
            let gen_ssh = chk_ssh.is_checked();
            let comment = inp_comment.value();

            let priv_trimmed = priv_path.trim().trim_matches('"').to_string();
            let pub_trimmed = pub_path.trim().trim_matches('"').to_string();

            if priv_trimmed.is_empty() || pub_trimmed.is_empty() {
                dialog::alert_default("Please specify output paths for both private and public keys!");
                return;
            }

            if std::path::Path::new(&priv_trimmed).is_dir() || std::path::Path::new(&pub_trimmed).is_dir() {
                dialog::alert_default("The output path is a directory.\nPlease specify a valid file name.");
                return;
            }

            global_run.store(true, Ordering::Relaxed);
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
            let global_run_clone = global_run.clone();

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
                let success = match crate::modules::keygen::KeyGen::generate_rsa_key_pair(bits, &priv_trimmed, &pub_trimmed) {
                    Ok(_) => {
                        report.push_str(&format!("[Success] RSA Key Pair generated successfully!\nPrivate Key: {}\nPublic Key: {}\n", priv_trimmed, pub_trimmed));
                        
                        if gen_ssh {
                            match crate::modules::keygen::KeyGen::load_private_key_from_file(&priv_trimmed) {
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
                    let global_run_inner = global_run_clone;
                    move || {
                        global_run_inner.store(false, Ordering::Relaxed);
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
    global_is_running: Arc<AtomicBool>,
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
        let global_run = global_is_running.clone();

        move |_| {
            progress.set_value(0.0);
            progress.set_label("0%");
            progress.redraw();

            let input_data = input_source.value();
            let mode = mode_choice.value();
            let alg_idx = alg_choice.value();

            let input_trimmed = input_data.trim().trim_matches('"').to_string();

            if input_trimmed.is_empty() {
                text_buffer.set_text("[Error] Please enter text or select a file path!\n");
                result_input.set_value("");
                return;
            }

            if mode == 0 && std::path::Path::new(&input_trimmed).is_dir() {
                dialog::alert_default("Directory hashing is not currently supported.\nPlease select a valid file.");
                return;
            }

            let algorithm = match alg_idx {
                1 => crate::modules::hashutil::HashAlgorithm::SHA1,
                2 => crate::modules::hashutil::HashAlgorithm::SHA256,
                3 => crate::modules::hashutil::HashAlgorithm::SHA3_256,
                _ => crate::modules::hashutil::HashAlgorithm::MD5,
            };
            let alg_name = algorithm.to_string();

            global_run.store(true, Ordering::Relaxed);
            btn_compute.deactivate();
            result_input.set_value("");
            text_buffer.set_text("");

            let mut tb_clone = text_buffer.clone();
            let mut prog_clone = progress.clone();
            let mut btn_comp_clone = btn_compute.clone();
            let mut res_inp_clone = result_input.clone();
            let global_run_clone = global_run.clone();

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
                    crate::modules::hashutil::HashUtil::compute_hash_from_file(&input_trimmed, algorithm, Some(callback))
                } else {
                    app::awake_callback({
                        let mut t = tb_clone.clone();
                        move || t.append("Calculating hash from text...\n")
                    });
                    let h = crate::modules::hashutil::HashUtil::compute_hash_from_text(&input_trimmed, algorithm);
                    app::awake_callback({
                        let mut p = prog_clone.clone();
                        move || {
                            p.set_value(100.0);
                            p.set_label("100%");
                        }
                    });
                    h
                };

                let global_run_inner = global_run_clone.clone();
                app::awake_callback(move || {
                    global_run_inner.store(false, Ordering::Relaxed);
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

pub fn setup_rsacrypt_callbacks(
    mut mode_choice: fltk::menu::Choice,
    btn_browse_key: &mut fltk::button::Button,
    input_key: fltk::input::Input,
    btn_browse_data: &mut fltk::button::Button,
    input_data: fltk::input::MultilineInput,
    btn_execute: &mut fltk::button::Button,
    btn_stop: &mut fltk::button::Button,
    result_input: fltk::input::MultilineInput,
    btn_copy: &mut fltk::button::Button,
    btn_clear: &mut fltk::button::Button,
    text_buffer: fltk::text::TextBuffer,
    progress: fltk::misc::Progress,
    global_is_running: Arc<AtomicBool>,
) {
    mode_choice.set_callback({
        let mut ik = input_key.clone();
        let mut id = input_data.clone();
        let mut ri = result_input.clone();
        let mut tb = text_buffer.clone();
        move |c| {
            ik.set_value("");
            id.set_value("");
            ri.set_value("");
            ri.set_label("");
            match c.value() {
                0 => {
                    tb.set_text("Switched to Hybrid Encryption (AES+RSA). Please select a Public Key.\nTip: You can input text or a valid file path!\n");
                    ri.set_readonly(true);
                    ri.set_label("Result (Base64):");
                    ri.set_color(fltk::enums::Color::from_rgb(39, 40, 34));
                    ri.set_text_color(fltk::enums::Color::from_rgb(166, 226, 46));
                },
                1 => {
                    tb.set_text("Switched to Hybrid Decryption (AES+RSA). Please select a Private Key.\nTip: You can input Base64 or a valid file path!\n");
                    ri.set_readonly(true);
                    ri.set_label("Result (Text):");
                    ri.set_color(fltk::enums::Color::from_rgb(39, 40, 34));
                    ri.set_text_color(fltk::enums::Color::from_rgb(166, 226, 46));
                },
                2 => {
                    tb.set_text("Switched to RSA Sign Mode. Please select a Private Key.\nTip: You can input text or a valid file path!\n");
                    ri.set_readonly(true);
                    ri.set_label("Sign (Base64):");
                    ri.set_color(fltk::enums::Color::from_rgb(39, 40, 34));
                    ri.set_text_color(fltk::enums::Color::from_rgb(166, 226, 46));
                },
                3 => {
                    tb.set_text("Switched to RSA Verify Mode. Select Public Key & paste signature below.\nTip: You can input text or a valid file path!\n");
                    ri.set_readonly(false);
                    ri.set_label("Verify Sig (B64):");
                    ri.set_color(fltk::enums::Color::from_rgb(255, 255, 255));
                    ri.set_text_color(fltk::enums::Color::from_rgb(0, 0, 0));
                },
                _ => {}
            }
            if let Some(mut parent) = ri.parent() {
                parent.redraw();
            }
        }
    });

    btn_browse_key.set_callback({
        let mut ik = input_key.clone();
        let mode = mode_choice.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseFile);
            let mode_val = mode.value();
            if mode_val == 0 || mode_val == 3 {
                dialog.set_title("Select RSA Public Key (*.pem, *.pub)");
            } else {
                dialog.set_title("Select RSA Private Key (*.pem)");
            }
            dialog.set_filter("PEM Files\t*.{pem,pub}\nAll Files\t*.*");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                ik.set_value(&path_str);
            }
        }
    });

    btn_browse_data.set_callback({
        let mut id = input_data.clone();
        move |_| {
            let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseFile);
            dialog.set_title("Select Input File");
            dialog.show();
            let path_str = dialog.filename().to_string_lossy().to_string();
            if !path_str.is_empty() {
                id.set_value(&path_str);
            }
        }
    });

    btn_stop.deactivate();
    let cancel_flag = Arc::new(AtomicBool::new(false));

    btn_stop.set_callback({
        let flag = cancel_flag.clone();
        move |_| {
            flag.store(true, Ordering::Relaxed);
        }
    });

    btn_execute.set_callback({
        let mode = mode_choice.clone();
        let ik = input_key.clone();
        let id = input_data.clone();
        let mut ri = result_input.clone();
        let tb = text_buffer.clone();
        let mut btn_ex = btn_execute.clone();
        let mut btn_stop_clone = btn_stop.clone();
        let mut prog = progress.clone();
        let global_run = global_is_running.clone();
        let flag = cancel_flag.clone();

        move |_| {
            let key_path = ik.value();
            let data = id.value();
            let mode_val = mode.value();
            let sig_val = ri.value();

            if key_path.is_empty() || data.is_empty() {
                dialog::alert_default("Please provide both a key file and data to process.");
                return;
            }

            if mode_val == 3 && sig_val.is_empty() {
                dialog::alert_default("Please provide the signature (Base64) to verify in the result field.");
                return;
            }

            let data_trimmed_check = data.trim().trim_matches('"');
            if std::path::Path::new(data_trimmed_check).is_dir() {
                dialog::alert_default("Directory processing is not currently supported.\nPlease select a valid file or input text.");
                return;
            }

            btn_ex.deactivate();
            btn_stop_clone.activate();
            if mode_val != 3 {
                ri.set_value("");
            }

            prog.set_value(0.0);
            prog.set_label("0%");
            prog.redraw();

            global_run.store(true, Ordering::Relaxed);
            flag.store(false, Ordering::Relaxed);
            
            let mut tb_clone = tb.clone();
            let mut ri_clone = ri.clone();
            let btn_ex_clone = btn_ex.clone();
            let btn_stop_clone2 = btn_stop_clone.clone();
            let prog_clone = prog.clone();
            let global_run_clone = global_run.clone();
            let flag_clone = flag.clone();
            
            enum RsaResult {
                TextOutput(String),
                FileSuccess(String),
                VerifySuccess,
            }

            std::thread::spawn(move || {
                let data_trimmed = data.trim().trim_matches('"');
                let is_file = std::path::Path::new(data_trimmed).is_file();

                let progress_cb = {
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

                let result_msg: Result<RsaResult, String> = match mode_val {
                    0 => {
                        match crate::modules::rsacrypt::RSACrypt::load_public_key(&key_path) {
                            Ok(pub_key) => {
                                if is_file {
                                    let out_path = format!("{}.enc", data_trimmed);
                                    app::awake_callback({ let mut t = tb_clone.clone(); let out = out_path.clone(); move || t.append(&format!("Hybrid Encrypting file to:\n{}\n", out)) });
                                    match crate::modules::rsacrypt::RSACrypt::hybrid_encrypt_file(&pub_key, data_trimmed, &out_path, Some(Box::new(progress_cb)), Some(flag_clone)) {
                                        Ok(_) => Ok(RsaResult::FileSuccess(format!("File successfully encrypted to:\n{}", out_path))),
                                        Err(e) => Err(e),
                                    }
                                } else {
                                    app::awake_callback({ let mut t = tb_clone.clone(); move || t.append("Hybrid Encrypting text (AES-256 + RSA)...\n") });
                                    match crate::modules::rsacrypt::RSACrypt::hybrid_encrypt_bytes(&pub_key, data.as_bytes()) {
                                        Ok(payload) => {
                                            use base64::{engine::general_purpose, Engine as _};
                                            Ok(RsaResult::TextOutput(general_purpose::STANDARD.encode(&payload)))
                                        },
                                        Err(e) => Err(e),
                                    }
                                }
                            },
                            Err(e) => Err(e),
                        }
                    },
                    1 => {
                        match crate::modules::rsacrypt::RSACrypt::load_private_key(&key_path) {
                            Ok(priv_key) => {
                                if is_file {
                                    let out_path = if data_trimmed.ends_with(".enc") {
                                        data_trimmed.strip_suffix(".enc").unwrap().to_string() + ".dec"
                                    } else {
                                        format!("{}.dec", data_trimmed)
                                    };
                                    app::awake_callback({ let mut t = tb_clone.clone(); let out = out_path.clone(); move || t.append(&format!("Hybrid Decrypting file to:\n{}\n", out)) });
                                    match crate::modules::rsacrypt::RSACrypt::hybrid_decrypt_file(&priv_key, data_trimmed, &out_path, Some(Box::new(progress_cb)), Some(flag_clone)) {
                                        Ok(_) => Ok(RsaResult::FileSuccess(format!("File successfully decrypted to:\n{}", out_path))),
                                        Err(e) => Err(e),
                                    }
                                } else {
                                    app::awake_callback({ let mut t = tb_clone.clone(); move || t.append("Hybrid Decrypting text (AES-256 + RSA)...\n") });
                                    use base64::{engine::general_purpose, Engine as _};
                                    match general_purpose::STANDARD.decode(&data) {
                                        Ok(payload) => {
                                            match crate::modules::rsacrypt::RSACrypt::hybrid_decrypt_bytes(&priv_key, &payload) {
                                                Ok(plaintext) => {
                                                    match String::from_utf8(plaintext) {
                                                        Ok(s) => Ok(RsaResult::TextOutput(s)),
                                                        Err(_) => Err("Decrypted data is not a valid UTF-8 string.".to_string()),
                                                    }
                                                },
                                                Err(e) => Err(e),
                                            }
                                        },
                                        Err(e) => Err(format!("Base64 decoding failed: {}", e)),
                                    }
                                }
                            },
                            Err(e) => Err(e),
                        }
                    },
                    2 => {
                        app::awake_callback({ let mut t = tb_clone.clone(); move || t.append("Signing data...\n") });
                        match crate::modules::rsacrypt::RSACrypt::load_private_key(&key_path) {
                            Ok(priv_key) => {
                                let data_bytes = if is_file {
                                    std::fs::read(data_trimmed).map_err(|e| format!("Read file failed: {}", e))
                                } else {
                                    Ok(data.as_bytes().to_vec())
                                };
                                match data_bytes {
                                    Ok(bytes) => {
                                        match crate::modules::rsacrypt::RSACrypt::sign(&priv_key, &bytes) {
                                            Ok(sig_bytes) => {
                                                use base64::{engine::general_purpose, Engine as _};
                                                    Ok(RsaResult::TextOutput(general_purpose::STANDARD.encode(&sig_bytes)))
                                            },
                                            Err(e) => Err(e),
                                        }
                                    },
                                    Err(e) => Err(e),
                                }
                            },
                            Err(e) => Err(e),
                        }
                    },
                    3 => {
                        let sig_b64 = sig_val.clone();
                        app::awake_callback({ let mut t = tb_clone.clone(); move || t.append("Verifying signature...\n") });
                        match crate::modules::rsacrypt::RSACrypt::load_public_key(&key_path) {
                            Ok(pub_key) => {
                                use base64::{engine::general_purpose, Engine as _};
                                match general_purpose::STANDARD.decode(&sig_b64) {
                                    Ok(sig_bytes) => {
                                        let data_bytes = if is_file {
                                            std::fs::read(data_trimmed).map_err(|e| format!("Read file failed: {}", e))
                                        } else {
                                            Ok(data.as_bytes().to_vec())
                                        };
                                        match data_bytes {
                                            Ok(bytes) => {
                                                match crate::modules::rsacrypt::RSACrypt::verify(&pub_key, &bytes, &sig_bytes) {
                                                        Ok(_) => Ok(RsaResult::VerifySuccess),
                                                    Err(e) => Err(e),
                                                }
                                            },
                                            Err(e) => Err(e),
                                        }
                                    },
                                    Err(e) => Err(format!("Signature Base64 decoding failed: {}", e)),
                                }
                            },
                            Err(e) => Err(e),
                        }
                    },
                    _ => Err("Unknown mode selected.".to_string()),
                };

                app::awake_callback({
                    let mut prg = prog_clone;
                    let global_run_inner = global_run_clone;
                    let mut start_btn = btn_ex_clone;
                    let mut stop_btn = btn_stop_clone2;
                    move || {
                        global_run_inner.store(false, Ordering::Relaxed);
                        start_btn.activate();
                        stop_btn.deactivate();

                        match &result_msg {
                            Ok(RsaResult::TextOutput(res_str)) => {
                                tb_clone.append("[Success] Operation completed successfully!\n");
                                ri_clone.set_value(res_str);
                                prg.set_value(100.0);
                                prg.set_label("100%");
                            },
                            Ok(RsaResult::FileSuccess(msg)) => {
                                tb_clone.append(&format!("[Success] {}\n", msg));
                                ri_clone.set_value("");
                                dialog::message_default(&format!("Operation Successful:\n{}", msg));
                                prg.set_value(100.0);
                                prg.set_label("100%");
                            },
                            Ok(RsaResult::VerifySuccess) => {
                                tb_clone.append("[Success] Signature Verification Passed! The data is authentic.\n");
                                dialog::message_default("Signature Valid!\nThe message is authentic and has not been tampered with.");
                                prg.set_value(100.0);
                                prg.set_label("100%");
                            },
                            Err(err_msg) => {
                                tb_clone.append(&format!("[Error] {}\n", err_msg));
                                if err_msg != "Operation cancelled." {
                                    dialog::alert_default(&format!("Operation failed:\n{}", err_msg));
                                }
                                prg.set_value(0.0);
                                prg.set_label("0%");
                            }
                        }
                    }
                });
            });
        }
    });

    btn_copy.set_callback({
        let ri = result_input.clone();
        let mut tb = text_buffer.clone();
        move |_| {
            let val = ri.value();
            if !val.is_empty() {
                app::copy(&val);
                tb.append("Result copied to clipboard.\n");
                dialog::message_default("[Success] Copied to clipboard!");
            } else {
                dialog::alert_default("[Error] No result to copy!");
            }
        }
    });

    btn_clear.set_callback({
        let mut ik = input_key.clone();
        let mut id = input_data.clone();
        let mut ri = result_input.clone();
        let mut tb = text_buffer.clone();
        let mut prog = progress.clone();
        move |_| {
            ik.set_value("");
            id.set_value("");
            ri.set_value("");
            tb.set_text("RSA Crypt matrix reset. System ready.\n");
            prog.set_value(0.0);
            prog.set_label("0%");
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
    disp.wrap_mode(fltk::text::WrapMode::AtBounds, 0);

    let mut btn_ok = fltk::button::Button::default().with_pos(250, 360).with_size(100, 30).with_label("OK");
    btn_ok.set_callback({ let mut w = win.clone(); move |_| w.hide() });

    win.end();
    
    let (sw, sh) = app::screen_size();
    win.set_pos(((sw as i32) - win.w()) / 2, ((sh as i32) - win.h()) / 2);
    win.show();
}

pub fn show_readme_dialog() {
    let mut win = fltk::window::Window::default()
        .with_size(700, 500)
        .with_label("README - Kitana Cryptool");
    win.make_modal(true);
    
    let mut disp = fltk::text::TextDisplay::default().with_size(680, 430).with_pos(10, 10);
    let mut buf = fltk::text::TextBuffer::default();
    
    // 根據系統 locale 自動決定顯示中文或英文 README
    let locale = sys_locale::get_locale().unwrap_or_else(|| "en".to_string());
    let readme_content = if locale.to_lowercase().starts_with("zh") {
        include_str!("../../README_zh.md")
    } else {
        include_str!("../../README.md")
    };
    
    buf.set_text(readme_content);
    disp.set_buffer(buf);
    disp.set_text_font(fltk::enums::Font::Courier); // 使用等寬字型讓 Markdown 排版更整齊
    disp.set_text_size(14);
    disp.wrap_mode(fltk::text::WrapMode::AtBounds, 0); // 啟用自動換行，讓文字在視窗邊界自動折行

    let mut btn_ok = fltk::button::Button::default().with_pos(300, 450).with_size(100, 30).with_label("Close");
    btn_ok.set_callback({ let mut w = win.clone(); move |_| w.hide() });

    win.end();
    
    let (sw, sh) = app::screen_size();
    win.set_pos(((sw as i32) - win.w()) / 2, ((sh as i32) - win.h()) / 2);
    win.show();
}

pub fn show_about_dialog() {
    let mut dialog = fltk::window::Window::default()
        .with_size(460, 470)
        .with_label("About");
    dialog.make_modal(true);

    let about_html = format!(
        "<html><body><font face='Microsoft JhengHei, Segoe UI' size='3'>\
        <b>Kitana Cryptool - Crypto Engine Matrix</b> (Version {})<br>&nbsp;<br>\
        This project is developed using Rust and FLTK.<br>&nbsp;<br>\
        <b>Used libraries and licenses:</b><br>\
        fltk-rs: 1.5 (License: MIT / LGPL)<br>\
        RustCrypto (aes, cbc, cipher, md-5, pbkdf2, rsa, sha1, sha2, sha3, signature): (License: MIT / Apache 2.0)<br>\
        rand, getrandom: (License: MIT / Apache 2.0)<br>\
        base64: (License: MIT / Apache 2.0)<br>\
        sys-locale: (License: MIT / Apache 2.0)<br>\
        webbrowser: (License: MIT / Apache 2.0)<br>\
        winres: (License: MIT)<br>&nbsp;<br>\
        This software itself is licensed under the <b>MIT License</b>.<br>\
        <i>See the LICENSE file in the project for detailed licensing terms.</i>\
        </font></body></html>",
        env!("CARGO_PKG_VERSION")
    );

    let mut about_label = fltk::misc::HelpView::default().with_pos(20, 20).with_size(420, 270);
    about_label.set_color(dialog.color());
    about_label.set_value(&about_html);

    let mut icon_box = fltk::frame::Frame::default().with_pos(198, 290).with_size(64, 64);
    icon_box.set_frame(fltk::enums::FrameType::FlatBox);
    icon_box.set_color(dialog.color());

    if let Ok(mut img) = fltk::image::PngImage::from_data(include_bytes!("../../app.png")) {
        img.scale(64, 64, true, true);
        icon_box.set_image(Some(img));
    } else {
        icon_box.set_label("Load Fail");
    }

    let mut btn_mit = fltk::button::Button::default().with_pos(25, 370).with_size(120, 28).with_label("MIT License");
    let mut btn_lgpl = fltk::button::Button::default().with_pos(170, 370).with_size(120, 28).with_label("LGPL License");
    let mut btn_apache = fltk::button::Button::default().with_pos(315, 370).with_size(120, 28).with_label("Apache License");

    btn_mit.set_callback(|_| show_license_dialog("MIT License", include_str!("../../licenses/mit.txt")));
    btn_lgpl.set_callback(|_| show_license_dialog("LGPL License", include_str!("../../licenses/lgpl-3.0.txt")));
    btn_apache.set_callback(|_| show_license_dialog("Apache License", include_str!("../../licenses/apache-2.0.txt")));

    let mut btn_ok = fltk::button::Button::default().with_pos(180, 420).with_size(100, 30).with_label("OK");
    btn_ok.set_callback({ let mut d = dialog.clone(); move |_| d.hide() });

    dialog.end();
    let (sw, sh) = app::screen_size();
    dialog.set_pos(((sw as i32) - dialog.w()) / 2, ((sh as i32) - dialog.h()) / 2);
    dialog.show();
}
