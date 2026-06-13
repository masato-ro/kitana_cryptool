#![cfg_attr(not(test), windows_subsystem = "windows")]

mod modules;

use fltk::{prelude::*, *};
use fltk::misc::Progress;

fn main() {
    let app = app::App::default();
    app::set_scheme(app::Scheme::Base);

    // 創建主窗口
    let mut wind = window::Window::default()
        .with_size(620, 555)
        .with_label("Kitana CryptoTool - Crypto Engine Matrix");

    // 設置視窗標題列圖標
    if let Ok(mut icon) = image::PngImage::from_data(include_bytes!("../app.png")) {
        icon.scale(64, 64, true, true);
        wind.set_icon(Some(icon));
    }

    // ===============================================================
    // TAB 1: AES Crypt
    // ===============================================================
    let tabs = group::Tabs::default()
        .with_pos(10, 35)
        .with_size(600, 225);

    let aes_group = group::Group::default()
        .with_pos(10, 60)
        .with_size(600, 200)
        .with_label("AES Crypt");

    let mut mode_choice = menu::Choice::default()
        .with_pos(120, 80)
        .with_size(470, 25)
        .with_label("Mode:");
    mode_choice.add_choice("Encrypt|Decrypt");
    mode_choice.set_value(0);

    let input_file = input::Input::default()
        .with_pos(120, 115)
        .with_size(380, 25)
        .with_label("Input File:");
    let mut btn_browse_in = button::Button::default()
        .with_pos(510, 115)
        .with_size(80, 25)
        .with_label("Browse...");

    let output_file = input::Input::default()
        .with_pos(120, 150)
        .with_size(380, 25)
        .with_label("Output File:");
    let mut btn_browse_out = button::Button::default()
        .with_pos(510, 150)
        .with_size(80, 25)
        .with_label("Browse...");

    let password_input = input::SecretInput::default()
        .with_pos(120, 185)
        .with_size(470, 25)
        .with_label("Password:");

    let mut btn_start = button::Button::default()
        .with_pos(30, 220)
        .with_size(100, 30)
        .with_label("Start");

    let mut btn_stop = button::Button::default()
        .with_pos(140, 220)
        .with_size(100, 30)
        .with_label("Stop");

    let mut btn_clear = button::Button::default()
        .with_pos(250, 220)
        .with_size(100, 30)
        .with_label("Clear");

    aes_group.end();

    // ===============================================================
    // TAB 2: RSA Crypt
    // ===============================================================
    let mut rsa_group = group::Group::default()
        .with_pos(10, 60)
        .with_size(600, 200)
        .with_label("RSA Crypt");

    let mut rsa_mode_choice = menu::Choice::default()
        .with_pos(120, 80)
        .with_size(470, 25)
        .with_label("Mode:");
    rsa_mode_choice.add_choice("Encrypt (Public Key)|Decrypt (Private Key)|Sign (Private Key)|Verify (Public Key)");
    rsa_mode_choice.set_value(0);

    let rsa_input_key = input::Input::default()
        .with_pos(120, 115)
        .with_size(380, 25)
        .with_label("Key File:");
    let mut btn_rsa_browse_key = button::Button::default()
        .with_pos(510, 115)
        .with_size(80, 25)
        .with_label("Browse...");

    let rsa_input_data = input::Input::default()
        .with_pos(120, 150)
        .with_size(470, 25)
        .with_label("Input Data:");

    let mut rsa_result_input = input::Input::default()
        .with_pos(120, 185)
        .with_size(470, 25)
        .with_label("Result:");
    rsa_result_input.set_color(enums::Color::from_rgb(245, 245, 245));
    rsa_result_input.set_readonly(true);

    let mut btn_rsa_execute = button::Button::default()
        .with_pos(30, 220)
        .with_size(100, 30)
        .with_label("Execute");

    let mut btn_rsa_copy = button::Button::default()
        .with_pos(140, 220)
        .with_size(100, 30)
        .with_label("Copy Result");

    let mut btn_rsa_clear = button::Button::default()
        .with_pos(250, 220)
        .with_size(100, 30)
        .with_label("Clear");

    rsa_group.end();
    rsa_group.hide();

    // ===============================================================
    // TAB 3: KeyGen
    // ===============================================================
    let mut keygen_group = group::Group::default()
        .with_pos(10, 60)
        .with_size(600, 200)
        .with_label("KeyGen");

    let mut choice_bits = menu::Choice::default()
        .with_pos(160, 80)
        .with_size(430, 25)
        .with_label("Key Length");
    choice_bits.add_choice("1024|2048|4096");
    choice_bits.set_value(1);

    let input_priv = input::Input::default()
        .with_pos(160, 115)
        .with_size(340, 25)
        .with_label("Private Key Output");
    let mut btn_browse_priv = button::Button::default()
        .with_pos(510, 115)
        .with_size(80, 25)
        .with_label("Browse...");

    let input_pub = input::Input::default()
        .with_pos(160, 150)
        .with_size(340, 25)
        .with_label("Public Key Output");
    let mut btn_browse_pub = button::Button::default()
        .with_pos(510, 150)
        .with_size(80, 25)
        .with_label("Browse...");

    let mut check_ssh = button::CheckButton::default()
        .with_pos(30, 185)
        .with_size(250, 25)
        .with_label("Generate OpenSSH Public Key.");
    check_ssh.set_tooltip("Check this to additionally generate an OpenSSH format public key,\nwhich can be copied to your clipboard after generation.");

    let mut input_comment = input::Input::default()
        .with_pos(420, 185)
        .with_size(170, 25)
        .with_label("Comment:");
    input_comment.deactivate();

    let mut btn_generate_key = button::Button::default()
        .with_pos(30, 220)
        .with_size(110, 30)
        .with_label("Generate Key");

    let mut btn_copy_ssh = button::Button::default()
        .with_pos(150, 220)
        .with_size(130, 30)
        .with_label("Copy SSH Pub Key");

    let mut btn_keygen_clear = button::Button::default()
        .with_pos(290, 220)
        .with_size(100, 30)
        .with_label("Clear");

    keygen_group.end();
    keygen_group.hide();

    // ===============================================================
    // TAB 4: PasswdGen
    // ===============================================================
    let mut passwdgen_group = group::Group::default()
        .with_pos(10, 60)
        .with_size(600, 200)
        .with_label("PasswdGen");

    let mut slider_len = valuator::ValueSlider::default()
        .with_pos(120, 80)
        .with_size(470, 25)
        .with_label("Length:");
    slider_len.set_type(valuator::SliderType::Horizontal);
    slider_len.set_bounds(8.0, 64.0);
    slider_len.set_value(16.0);
    slider_len.set_step(1.0, 1);
    slider_len.set_align(enums::Align::Left);

    let chk_upper = button::CheckButton::default().with_pos(30, 115).with_size(120, 25).with_label("Uppercase");
    chk_upper.set_checked(true);
    let chk_lower = button::CheckButton::default().with_pos(160, 115).with_size(120, 25).with_label("Lowercase");
    chk_lower.set_checked(true);
    let chk_digits = button::CheckButton::default().with_pos(290, 115).with_size(120, 25).with_label("Digits");
    chk_digits.set_checked(true);
    let chk_symbols = button::CheckButton::default().with_pos(420, 115).with_size(120, 25).with_label("Symbols");
    chk_symbols.set_checked(true);

    let input_passwd = input::Input::default().with_pos(120, 150).with_size(470, 25).with_label("Password:");

    let mut progress_strength = misc::Progress::default().with_pos(120, 185).with_size(470, 15).with_label("");
    progress_strength.set_minimum(0.0);
    progress_strength.set_maximum(100.0);
    progress_strength.set_color(enums::Color::from_rgb(200, 200, 200));

    let mut btn_generate_passwd = button::Button::default().with_pos(30, 220).with_size(150, 30).with_label("Generate Password");

    let mut btn_copy_passwd = button::Button::default().with_pos(190, 220).with_size(150, 30).with_label("Copy Password");

    let mut btn_passwd_clear = button::Button::default().with_pos(350, 220).with_size(100, 30).with_label("Clear");

    passwdgen_group.end();
    passwdgen_group.hide();

    // ===============================================================
    // TAB 5: Hash Matrix
    // ===============================================================
    let mut hash_group = group::Group::default()
        .with_pos(10, 60)
        .with_size(600, 200)
        .with_label("Hash Matrix");

    let mut hash_mode_choice = menu::Choice::default()
        .with_pos(120, 80)
        .with_size(170, 25)
        .with_label("Target Type:");
    hash_mode_choice.add_choice("File Path|Plain Text");
    hash_mode_choice.set_value(0);

    let mut hash_alg_choice = menu::Choice::default()
        .with_pos(420, 80)
        .with_size(170, 25)
        .with_label("Algorithm:");
    hash_alg_choice.add_choice("MD5|SHA-1|SHA-256|SHA-3-256");
    hash_alg_choice.set_value(2);

    let hash_input_source = input::Input::default()
        .with_pos(120, 115)
        .with_size(380, 25)
        .with_label("Source Input:");

    let mut btn_hash_browse = button::Button::default().with_pos(510, 115).with_size(80, 25).with_label("Browse...");

    let mut hash_result_input = input::Input::default().with_pos(120, 150).with_size(380, 25).with_label("Hash Result:");
    hash_result_input.set_color(enums::Color::from_rgb(245, 245, 245));
    hash_result_input.set_readonly(true);

    let mut btn_hash_compare = button::Button::default().with_pos(510, 150).with_size(80, 25).with_label("Compare...");

    let mut btn_hash_compute = button::Button::default().with_pos(30, 220).with_size(140, 30).with_label("Compute Hash");

    let mut btn_hash_copy = button::Button::default().with_pos(180, 220).with_size(120, 30).with_label("Copy Hash");

    let mut btn_hash_clear = button::Button::default().with_pos(310, 220).with_size(100, 30).with_label("Clear");

    hash_group.end();
    hash_group.hide();

    tabs.end();

    // ===============================================================
    // Menu Bar
    // ===============================================================
    let mut menu_bar = menu::SysMenuBar::default().with_size(620, 25);
    menu_bar.add("&File/&Exit\t", enums::Shortcut::Alt | 'q', menu::MenuFlag::Normal, |_| app::quit());

    menu_bar.add("&Mode/AES Crypt\t", enums::Shortcut::Alt | '1', menu::MenuFlag::Normal, {
        let mut t = tabs.clone();
        let g = aes_group.clone();
        move |_| { let _ = t.set_value(&g); }
    });

    menu_bar.add("&Mode/RSA Crypt\t", enums::Shortcut::Alt | '2', menu::MenuFlag::Normal, {
        let mut t = tabs.clone();
        let g = rsa_group.clone();
        move |_| { let _ = t.set_value(&g); }
    });

    menu_bar.add("&Mode/KeyGen\t", enums::Shortcut::Alt | '3', menu::MenuFlag::Normal, {
        let mut t = tabs.clone();
        let g = keygen_group.clone();
        move |_| { let _ = t.set_value(&g); }
    });

    menu_bar.add("&Mode/PasswdGen\t", enums::Shortcut::Alt | '4', menu::MenuFlag::Normal, {
        let mut t = tabs.clone();
        let g = passwdgen_group.clone();
        move |_| { let _ = t.set_value(&g); }
    });

    menu_bar.add("&Mode/Hash Matrix\t", enums::Shortcut::Alt | '5', menu::MenuFlag::Normal, {
        let mut t = tabs.clone();
        let g = hash_group.clone();
        move |_| { let _ = t.set_value(&g); }
    });

    menu_bar.add("&Help/&README\t", enums::Shortcut::None, menu::MenuFlag::Normal, |_| crate::modules::ui_callbacks::show_readme_dialog());
    menu_bar.add("&Help/&About\t", enums::Shortcut::None, menu::MenuFlag::Normal, |_| crate::modules::ui_callbacks::show_about_dialog());

    // 狀態顯示
    let mut status_display = text::TextDisplay::default()
        .with_size(600, 220)
        .with_pos(10, 270);
    let mut text_buffer = text::TextBuffer::default();
    text_buffer.set_text("Status messages will be displayed here...\n");
    status_display.set_buffer(text_buffer.clone());
    status_display.set_color(enums::Color::from_rgb(39, 40, 34));      // Monokai Background
    status_display.set_text_color(enums::Color::from_rgb(166, 226, 46)); // Monokai Green
    status_display.set_text_font(enums::Font::Courier);

    // 進度條
    let mut progress = Progress::default()
        .with_size(600, 25)
        .with_pos(10, 505)
        .with_label("0%");
    progress.set_minimum(0.0);
    progress.set_maximum(100.0);
    progress.set_color(enums::Color::from_rgb(230, 230, 230));
    progress.set_selection_color(enums::Color::from_rgb(70, 150, 220));

    wind.end();
    wind.show();

    // ===============================================================
    // Callbacks
    // ===============================================================
    crate::modules::ui_callbacks::setup_aes_callbacks(
        &mut btn_browse_in,
        &mut btn_browse_out,
        &mut btn_start,
        &mut btn_stop,
        &mut btn_clear,
        input_file.clone(),
        output_file.clone(),
        password_input.clone(),
        mode_choice.clone(),
        text_buffer.clone(),
        progress.clone(),
    );

    crate::modules::ui_callbacks::setup_keygen_callbacks(
        &mut btn_browse_priv,
        &mut btn_browse_pub,
        &mut check_ssh,
        &mut btn_generate_key,
        &mut btn_copy_ssh,
        &mut btn_keygen_clear,
        choice_bits.clone(),
        input_priv.clone(),
        input_pub.clone(),
        input_comment.clone(),
        text_buffer.clone(),
        progress.clone(),
    );

    crate::modules::ui_callbacks::setup_passwdgen_callbacks(
        &mut btn_generate_passwd,
        &mut btn_copy_passwd,
        &mut btn_passwd_clear,
        slider_len.clone(),
        chk_upper.clone(),
        chk_lower.clone(),
        chk_digits.clone(),
        chk_symbols.clone(),
        input_passwd.clone(),
        progress_strength.clone(),
        text_buffer.clone(),
        progress.clone(),
    );

    crate::modules::ui_callbacks::setup_hash_callbacks(
        hash_mode_choice.clone(),
        &mut btn_hash_browse,
        hash_input_source.clone(),
        hash_alg_choice.clone(),
        &mut btn_hash_compute,
        hash_result_input.clone(),
        &mut btn_hash_compare,
        &mut btn_hash_copy,
        &mut btn_hash_clear,
        text_buffer.clone(),
        progress.clone(),
    );

    crate::modules::ui_callbacks::setup_rsacrypt_callbacks(
        rsa_mode_choice.clone(),
        &mut btn_rsa_browse_key,
        rsa_input_key.clone(),
        rsa_input_data.clone(),
        &mut btn_rsa_execute,
        rsa_result_input.clone(),
        &mut btn_rsa_copy,
        &mut btn_rsa_clear,
        text_buffer.clone(),
    );

    app.run().unwrap();
}