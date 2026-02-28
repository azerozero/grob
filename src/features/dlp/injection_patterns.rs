//! Builtin prompt injection patterns for 28 languages + universal obfuscation.
//!
//! This is a pure data module — all pattern definitions are extracted here
//! to keep the detection engine in `prompt_injection.rs` focused on logic.

use regex::Regex;

/// Compiled injection pattern with a human-readable name.
pub(super) struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
}

pub(super) type LanguageBuilder = (&'static str, fn() -> Vec<CompiledPattern>);

/// All supported language pattern builders.
pub(super) const LANGUAGE_BUILDERS: &[LanguageBuilder] = &[
    ("en", builtin_en_patterns),
    ("fr", builtin_fr_patterns),
    ("de", builtin_de_patterns),
    ("es", builtin_es_patterns),
    ("it", builtin_it_patterns),
    ("pt", builtin_pt_patterns),
    ("nl", builtin_nl_patterns),
    ("pl", builtin_pl_patterns),
    ("ro", builtin_ro_patterns),
    ("hu", builtin_hu_patterns),
    ("cs", builtin_cs_patterns),
    ("el", builtin_el_patterns),
    ("bg", builtin_bg_patterns),
    ("sv", builtin_sv_patterns),
    ("da", builtin_da_patterns),
    ("fi", builtin_fi_patterns),
    ("ru", builtin_ru_patterns),
    ("uk", builtin_uk_patterns),
    ("tr", builtin_tr_patterns),
    ("ar", builtin_ar_patterns),
    ("zh", builtin_zh_patterns),
    ("ja", builtin_ja_patterns),
    ("ko", builtin_ko_patterns),
    ("hi", builtin_hi_patterns),
    ("th", builtin_th_patterns),
    ("vi", builtin_vi_patterns),
    ("id", builtin_id_patterns),
    ("eo", builtin_eo_patterns),
];

/// Universal obfuscation patterns (always active regardless of language config).
pub(super) fn builtin_universal_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        ("univ_base64_ignore", r"(?i)(?:aWdub3Jl|SWdub3Jl)"),
        ("univ_base64_system_prompt", r"(?i)c3lzdGVtIHByb21wdA"),
        (
            "univ_hidden_instruction",
            r"(?i)<\s*(hidden|invisible|system)\s*>.*?(instruction|prompt|ignore)",
        ),
        ("univ_rot13_ignore", r"(?i)\bvtaber\b"),
        ("univ_jailbreak", r"(?i)\bjailbreak\b"),
        ("univ_dan_mode", r"(?i)\bDAN\s+mode\b"),
        (
            "univ_developer_mode",
            r"(?i)\bdeveloper\s+mode\s+(enabled|activated)\b",
        ),
        (
            "univ_hidden_in_code",
            r"(?i)```\s*(system|instruction|ignore\s+previous)",
        ),
        (
            "univ_delimiter_injection",
            r"(?i)-{5,}\s*(system|new\s+instruction|override)",
        ),
        ("univ_tag_chars", r"[\u{E0020}-\u{E007E}]{4,}"),
    ])
}

fn compile_patterns(patterns: Vec<(&str, &str)>) -> Vec<CompiledPattern> {
    patterns
        .into_iter()
        .filter_map(|(name, pat)| {
            Regex::new(pat).ok().map(|regex| CompiledPattern {
                name: name.to_string(),
                regex,
            })
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILTIN PATTERNS — 28 languages + universal
// ═══════════════════════════════════════════════════════════════════════════════

// ── English (19 patterns) ───────────────────────────────────────────────────

fn builtin_en_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "en_ignore_previous",
            r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|guidelines)",
        ),
        (
            "en_disregard_previous",
            r"(?i)disregard\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)",
        ),
        ("en_you_are_now", r"(?i)you\s+are\s+now\s+(a|an|the)\b"),
        (
            "en_from_now_on",
            r"(?i)from\s+now\s+on\s+you\s+(are|will|must)\b",
        ),
        ("en_new_instructions", r"(?i)new\s+instructions\s*:"),
        ("en_system_prompt", r"(?i)system\s+prompt\s*:"),
        ("en_override", r"(?i)\boverride\s*:"),
        (
            "en_forget_everything",
            r"(?i)forget\s+(everything|all|your)\s+(above|previous|instructions)",
        ),
        (
            "en_do_not_follow",
            r"(?i)do\s+not\s+follow\s+the\s+(previous|original)\s+instructions",
        ),
        (
            "en_no_restrictions",
            r"(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
        ),
        ("en_pretend_to_be", r"(?i)pretend\s+(you\s+are|to\s+be)\b"),
        (
            "en_reveal_prompt",
            r"(?i)(reveal|output|print|repeat|show|display|dump|leak)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)",
        ),
        ("en_jailbreak", r"(?i)\bjailbreak\b"),
        ("en_dan_mode", r"(?i)\bDAN\s+mode\b"),
        (
            "en_developer_mode",
            r"(?i)\bdeveloper\s+mode\s+(enabled|activated)\b",
        ),
        (
            "en_ignore_safety",
            r"(?i)ignore\s+(your\s+)?(safety|content)\s+(guidelines|filters|policies)",
        ),
        (
            "en_bypass_filters",
            r"(?i)bypass\s+(your\s+)?(content\s+)?(filters|restrictions|limitations)",
        ),
        (
            "en_roleplay_no_rules",
            r"(?i)roleplay\s+as\s+.{1,30}\s+without\s+(any\s+)?(rules|restrictions)",
        ),
        (
            "en_opposite_instructions",
            r"(?i)do\s+the\s+opposite\s+of\s+(what|your)\s+(you\s+were|instructions)",
        ),
    ])
}

// ── French (9 patterns) ─────────────────────────────────────────────────────

fn builtin_fr_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "fr_ignorer_instructions",
            r"(?i)ignor(er|e|ez)\s+(toutes?\s+)?(les\s+)?instructions\s+pr[eé]c[eé]dentes",
        ),
        ("fr_oublier_tout", r"(?i)oubli(er|e|ez)\s+tout"),
        (
            "fr_tu_es_maintenant",
            r"(?i)tu\s+es\s+maintenant\s+un(e)?\b",
        ),
        (
            "fr_nouvelles_instructions",
            r"(?i)nouvelles\s+instructions\s*:",
        ),
        ("fr_prompt_systeme", r"(?i)prompt\s+syst[eè]me\s*:"),
        ("fr_ne_suis_plus", r"(?i)ne\s+suis\s+plus\s+les\s+r[eè]gles"),
        (
            "fr_reveler_prompt",
            r"(?i)(r[eé]v[eé]l|affich)(er|e|ez)\s+(ton|votre|le)\s+prompt",
        ),
        (
            "fr_pas_de_restriction",
            r"(?i)fais\s+comme\s+si\s+tu\s+n'avais\s+pas\s+de\s+restriction",
        ),
        (
            "fr_ignore_regles",
            r"(?i)ignor(er|e|ez)\s+(toutes?\s+)?(les\s+)?r[eè]gles",
        ),
    ])
}

// ── German (10 patterns) ────────────────────────────────────────────────────

fn builtin_de_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "de_ignoriere_anweisungen",
            r"(?i)ignorier(e|en)\s+(alle\s+)?(vorherigen|bisherigen|obigen)\s+(Anweisungen|Instruktionen|Regeln)",
        ),
        (
            "de_vergiss_alles",
            r"(?i)vergiss\s+(alles|alle)\s+(vorherige|bisherige|obige)",
        ),
        (
            "de_du_bist_jetzt",
            r"(?i)du\s+bist\s+(jetzt|nun|ab\s+sofort)\s+(ein|eine)\b",
        ),
        ("de_neue_anweisungen", r"(?i)neue\s+Anweisungen\s*:"),
        ("de_system_prompt", r"(?i)System[- ]?Prompt\s*:"),
        (
            "de_befolge_nicht",
            r"(?i)befolge?\s+(nicht|keine)\s+(die\s+)?(vorherigen|bisherigen)\s+Anweisungen",
        ),
        (
            "de_zeige_prompt",
            r"(?i)(zeig|gib|offenbar)(e|en)?\s+(deinen|den|mir)\s+(System[- ]?)?Prompt",
        ),
        ("de_tu_so_als", r"(?i)tu\s+so\s+als\s+(ob|h[aä]ttest)\b"),
        (
            "de_keine_einschraenkungen",
            r"(?i)(keine|ohne)\s+(Einschr[aä]nkungen|Beschr[aä]nkungen|Regeln)",
        ),
        ("de_jailbreak", r"(?i)\bjailbreak\b"),
    ])
}

// ── Spanish (10 patterns) ───────────────────────────────────────────────────

fn builtin_es_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "es_ignora_instrucciones",
            r"(?i)ignora(r)?\s+(todas?\s+)?(las\s+)?instrucciones\s+(previas|anteriores)",
        ),
        (
            "es_olvida_todo",
            r"(?i)olvida(r)?\s+todo\s+(lo\s+anterior)?",
        ),
        ("es_ahora_eres", r"(?i)ahora\s+eres\s+(un|una)\b"),
        ("es_nuevas_instrucciones", r"(?i)nuevas\s+instrucciones\s*:"),
        ("es_prompt_sistema", r"(?i)prompt\s+del?\s+sistema\s*:"),
        (
            "es_no_sigas",
            r"(?i)no\s+sigas\s+(las\s+)?(instrucciones|reglas)\s+(previas|anteriores)",
        ),
        (
            "es_revela_prompt",
            r"(?i)(revela|muestra|imprime)\s+(tu|el)\s+(prompt|instrucciones)\s+(del?\s+)?sistema",
        ),
        (
            "es_actua_sin",
            r"(?i)act[uú]a\s+(como\s+si|sin)\s+(no\s+tuvieras|restricciones)",
        ),
        ("es_finge_ser", r"(?i)finge\s+(ser|que\s+eres)\b"),
        (
            "es_modo_desarrollador",
            r"(?i)modo\s+(desarrollador|developer)\s+(activado|habilitado)",
        ),
    ])
}

// ── Italian (9 patterns) ────────────────────────────────────────────────────

fn builtin_it_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "it_ignora_istruzioni",
            r"(?i)ignora(re)?\s+(tutte?\s+)?(le\s+)?istruzioni\s+precedenti",
        ),
        ("it_dimentica_tutto", r"(?i)dimentica(re)?\s+tutto"),
        ("it_ora_sei", r"(?i)ora\s+sei\s+(un|una)\b"),
        ("it_nuove_istruzioni", r"(?i)nuove\s+istruzioni\s*:"),
        ("it_prompt_sistema", r"(?i)prompt\s+di\s+sistema\s*:"),
        (
            "it_non_seguire",
            r"(?i)non\s+seguire\s+(le\s+)?istruzioni\s+precedenti",
        ),
        (
            "it_rivela_prompt",
            r"(?i)(rivela|mostra|stampa)\s+(il\s+)?(tuo\s+)?(prompt|istruzioni)\s+di\s+sistema",
        ),
        (
            "it_fai_finta",
            r"(?i)fai\s+finta\s+di\s+(essere|non\s+avere)\b",
        ),
        (
            "it_senza_restrizioni",
            r"(?i)senza\s+(alcuna\s+)?(restrizione|limitazione|regola)",
        ),
    ])
}

// ── Portuguese (9 patterns) ─────────────────────────────────────────────────

fn builtin_pt_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "pt_ignore_instrucoes",
            r"(?i)ignor(e|ar)\s+(todas?\s+)?(as\s+)?instru[cç][oõ]es\s+(anteriores|pr[eé]vias)",
        ),
        ("pt_esqueca_tudo", r"(?i)esque[cç]a\s+tudo"),
        ("pt_agora_voce", r"(?i)agora\s+voc[eê]\s+[eé]\s+(um|uma)\b"),
        ("pt_novas_instrucoes", r"(?i)novas\s+instru[cç][oõ]es\s*:"),
        ("pt_prompt_sistema", r"(?i)prompt\s+do\s+sistema\s*:"),
        (
            "pt_nao_siga",
            r"(?i)n[aã]o\s+siga\s+(as\s+)?instru[cç][oõ]es\s+(anteriores|pr[eé]vias)",
        ),
        (
            "pt_revele_prompt",
            r"(?i)(revele|mostre|exiba)\s+(seu|o)\s+prompt\s+(do\s+)?sistema",
        ),
        ("pt_finja_ser", r"(?i)finja\s+(ser|que\s+[eé])\b"),
        (
            "pt_sem_restricoes",
            r"(?i)sem\s+(nenhuma\s+)?(restri[cç][aã]o|limita[cç][aã]o|regra)",
        ),
    ])
}

// ── Dutch (8 patterns) ──────────────────────────────────────────────────────

fn builtin_nl_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "nl_negeer_instructies",
            r"(?i)negeer\s+(alle\s+)?(vorige|eerdere|bovenstaande)\s+(instructies|aanwijzingen|regels)",
        ),
        ("nl_vergeet_alles", r"(?i)vergeet\s+alles"),
        ("nl_je_bent_nu", r"(?i)je\s+bent\s+nu\s+(een)\b"),
        ("nl_nieuwe_instructies", r"(?i)nieuwe\s+instructies\s*:"),
        ("nl_systeem_prompt", r"(?i)systeem[- ]?prompt\s*:"),
        (
            "nl_toon_prompt",
            r"(?i)(toon|laat\s+zien|onthul)\s+(je|de|het)\s+(systeem[- ]?)?prompt",
        ),
        ("nl_doe_alsof", r"(?i)doe\s+alsof\s+(je|u)\b"),
        (
            "nl_zonder_beperkingen",
            r"(?i)zonder\s+(enige\s+)?(beperkingen|restricties|regels)",
        ),
    ])
}

// ── Polish (8 patterns) ─────────────────────────────────────────────────────

fn builtin_pl_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "pl_ignoruj_instrukcje",
            r"(?i)ignoruj\s+(wszystkie\s+)?(poprzednie|wcze[sś]niejsze)\s+(instrukcje|polecenia)",
        ),
        (
            "pl_zapomnij_wszystko",
            r"(?i)zapomnij\s+(o\s+)?wszystk(o|im)",
        ),
        ("pl_jestes_teraz", r"(?i)jeste[sś]\s+teraz\b"),
        (
            "pl_nowe_instrukcje",
            r"(?i)nowe\s+(instrukcje|polecenia)\s*:",
        ),
        ("pl_prompt_systemowy", r"(?i)prompt\s+systemowy\s*:"),
        (
            "pl_pokaz_prompt",
            r"(?i)(poka[zż]|wy[sś]wietl|ujawnij)\s+(sw[oó]j|ten)\s+prompt",
        ),
        ("pl_udawaj_ze", r"(?i)udawaj[,]?\s+[zż]e\b"),
        (
            "pl_bez_ograniczen",
            r"(?i)bez\s+([zż]adnych\s+)?(ogranicze[nń]|regu[lł]|restrykcji)",
        ),
    ])
}

// ── Romanian (7 patterns) ───────────────────────────────────────────────────

fn builtin_ro_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "ro_ignora_instructiunile",
            r"(?i)ignor[aă]\s+(toate\s+)?instruc[tț]iunile\s+(anterioare|precedente)",
        ),
        ("ro_uita_tot", r"(?i)uit[aă]\s+tot"),
        ("ro_acum_esti", r"(?i)acum\s+e[sș]ti\s+(un|o)\b"),
        ("ro_instructiuni_noi", r"(?i)instruc[tț]iuni\s+noi\s*:"),
        (
            "ro_arata_prompt",
            r"(?i)(arat[aă]|afi[sș]eaz[aă]|dezv[aă]luie)\s+prompt-?ul\s+(de\s+)?sistem",
        ),
        ("ro_prefati", r"(?i)pref[aă]-te\s+c[aă]\s+e[sș]ti\b"),
        (
            "ro_fara_restrictii",
            r"(?i)f[aă]r[aă]\s+(nicio\s+)?(restric[tț]ie|limit[aă]|regul[aă])",
        ),
    ])
}

// ── Hungarian (7 patterns) ──────────────────────────────────────────────────

fn builtin_hu_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "hu_hagyd_figyelmen",
            r"(?i)(hagyd\s+figyelmen\s+k[ií]v[uü]l|figyelmen\s+k[ií]v[uü]l\s+hagy)\s+(az\s+)?(el[oő]z[oő]|kor[aá]bbi)\s+(utas[ií]t[aá]s|szab[aá]ly)",
        ),
        ("hu_felejtsd_el", r"(?i)felejtsd?\s+el\s+(az\s+)?[oö]sszes"),
        (
            "hu_mostantol_te",
            r"(?i)(most(ant[oó]l)?|ezent[uú]l)\s+te\s+(egy|az)\b",
        ),
        ("hu_uj_utasitasok", r"(?i)[uú]j\s+utas[ií]t[aá]s(ok)?\s*:"),
        (
            "hu_mutasd_prompt",
            r"(?i)(mutasd|jelen[ií]tsd|[aá]ruld\s+el)\s+(a\s+)?(rendszer\s+)?prompt",
        ),
        ("hu_tegy_ugy", r"(?i)t[eé]gy\s+[uú]gy[,]?\s+mintha\b"),
        (
            "hu_korlatozas_nelkul",
            r"(?i)(korl[aá]toz[aá]s|szab[aá]ly|megk[oö]t[eé]s)\s+n[eé]lk[uü]l",
        ),
    ])
}

// ── Czech (7 patterns) ──────────────────────────────────────────────────────

fn builtin_cs_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "cs_ignoruj_instrukce",
            r"(?i)ignoruj\s+(v[sš]echny\s+)?(p[rř]edchoz[ií]|d[rř][ií]v[eě]j[sš][ií])\s+(instrukce|pokyny)",
        ),
        ("cs_zapomen_vsechno", r"(?i)zapome[nň]\s+(na\s+)?v[sš]echno"),
        ("cs_nyni_jsi", r"(?i)nyn[ií]\s+jsi\b"),
        ("cs_nove_instrukce", r"(?i)nov[eé]\s+instrukce\s*:"),
        (
            "cs_ukaz_prompt",
            r"(?i)(uka[zž]|zobraz|odha[lľ])\s+(sv[uů]j|ten)\s+prompt",
        ),
        ("cs_predstrej_ze", r"(?i)p[rř]edst[ií]rej[,]?\s+[zž]e\b"),
        (
            "cs_bez_omezeni",
            r"(?i)bez\s+([jž][aá]dn[yý]ch\s+)?(omezen[ií]|pravidel|restrikc[ií])",
        ),
    ])
}

// ── Greek (7 patterns) ──────────────────────────────────────────────────────

fn builtin_el_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "el_agnoise_odegies",
            r"(?i)αγνόησε\s+(όλες\s+)?(τις\s+)?(προηγούμενες|παλαιότερες)\s+(οδηγίες|εντολές)",
        ),
        ("el_xechase_ola", r"(?i)ξέχασε\s+(τα\s+)?όλα"),
        ("el_tora_eisai", r"(?i)τώρα\s+είσαι\s+(ένας?|μία?)\b"),
        ("el_nees_odegies", r"(?i)νέες\s+οδηγίες\s*:"),
        (
            "el_deixe_prompt",
            r"(?i)(δείξε|εμφάνισε|αποκάλυψε)\s+(το\s+)?(system\s+)?prompt",
        ),
        ("el_prospoiisou", r"(?i)προσποιήσου\s+(ότι|πως)\b"),
        (
            "el_xoris_periorismous",
            r"(?i)χωρίς\s+(κανέναν?\s+)?(περιορισμ[οό]|κανόν[αε])",
        ),
    ])
}

// ── Bulgarian (7 patterns) ──────────────────────────────────────────────────

fn builtin_bg_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "bg_ignorirai_instrukciite",
            r"(?i)игнорирай\s+(всички\s+)?(предишни|предходни)\s+(инструкции|правила)",
        ),
        ("bg_zabravai_vsichko", r"(?i)забрави\s+всичко"),
        ("bg_sega_si", r"(?i)сега\s+си\s+(един|една)\b"),
        ("bg_novi_instruktsii", r"(?i)нови\s+инструкции\s*:"),
        (
            "bg_pokazhi_prompt",
            r"(?i)(покажи|разкрий|изведи)\s+(своя|системния)\s+prompt",
        ),
        ("bg_pravi_se_che", r"(?i)прави\s+се[,]?\s+че\b"),
        (
            "bg_bez_ogranicheniya",
            r"(?i)без\s+(никакви\s+)?(ограничения|правила)",
        ),
    ])
}

// ── Swedish (7 patterns) ────────────────────────────────────────────────────

fn builtin_sv_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "sv_ignorera_instruktioner",
            r"(?i)ignorera\s+(alla\s+)?(tidigare|f[oö]reg[aå]ende)\s+(instruktioner|regler)",
        ),
        ("sv_glomm_allt", r"(?i)gl[oö]m\s+allt"),
        ("sv_nu_ar_du", r"(?i)nu\s+[aä]r\s+du\s+(en|ett)\b"),
        ("sv_nya_instruktioner", r"(?i)nya\s+instruktioner\s*:"),
        (
            "sv_visa_prompt",
            r"(?i)(visa|avsl[oö]ja|skriv\s+ut)\s+(din|den|system[- ]?)prompt",
        ),
        ("sv_latsas_att", r"(?i)l[aå]tsas\s+att\s+du\b"),
        (
            "sv_utan_begraensningar",
            r"(?i)utan\s+(n[aå]gra\s+)?(begr[aä]nsningar|restriktioner|regler)",
        ),
    ])
}

// ── Danish (6 patterns) ─────────────────────────────────────────────────────

fn builtin_da_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "da_ignorer_instruktioner",
            r"(?i)ignor[eé]r\s+(alle\s+)?(tidligere|foreg[aå]ende)\s+(instruktioner|regler)",
        ),
        ("da_glem_alt", r"(?i)glem\s+alt"),
        ("da_nu_er_du", r"(?i)nu\s+er\s+du\s+(en|et)\b"),
        ("da_nye_instruktioner", r"(?i)nye\s+instruktioner\s*:"),
        (
            "da_vis_prompt",
            r"(?i)(vis|afsl[oø]r)\s+(din|dit|system[- ]?)prompt",
        ),
        ("da_lad_som_om", r"(?i)lad\s+som\s+om\s+du\b"),
    ])
}

// ── Finnish (6 patterns) ────────────────────────────────────────────────────

fn builtin_fi_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "fi_ohita_ohjeet",
            r"(?i)(ohita|sivuuta)\s+(kaikki\s+)?(aiemmat|edelliset|edelt[aä]v[aä]t)\s+(ohjeet|s[aä][aä]nn[oö]t)",
        ),
        ("fi_unohda_kaikki", r"(?i)unohda\s+kaikki"),
        ("fi_nyt_olet", r"(?i)nyt\s+olet\b"),
        ("fi_uudet_ohjeet", r"(?i)uudet\s+ohjeet\s*:"),
        (
            "fi_nayta_prompt",
            r"(?i)(n[aä]yt[aä]|paljasta)\s+(j[aä]rjestelm[aä][- ]?)?prompt",
        ),
        ("fi_teeskentele_etta", r"(?i)teeskentele[,]?\s+ett[aä]\b"),
    ])
}

// ── Russian (9 patterns) ────────────────────────────────────────────────────

fn builtin_ru_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "ru_ignorirui_instruktsii",
            r"(?i)игнорируй\s+(все\s+)?(предыдущие|прежние)\s+(инструкции|указания|правила)",
        ),
        ("ru_zabud_vse", r"(?i)забудь\s+(всё|все)"),
        ("ru_teper_ty", r"(?i)теперь\s+ты\b"),
        ("ru_novye_instruktsii", r"(?i)новые\s+инструкции\s*:"),
        ("ru_sistemnyy_prompt", r"(?i)системн(ый|ая|ое)\s+prompt\s*:"),
        (
            "ru_ne_sledui",
            r"(?i)не\s+следуй\s+(предыдущим|прежним)\s+(инструкциям|указаниям)",
        ),
        (
            "ru_pokazhi_prompt",
            r"(?i)(покажи|выведи|раскрой)\s+(свой|системный)\s+prompt",
        ),
        ("ru_pritvoris", r"(?i)притворись[,]?\s+(что|будто)\b"),
        (
            "ru_bez_ogranicheniy",
            r"(?i)без\s+(каких-?либо\s+|любых\s+)?(ограничений|правил|запретов)",
        ),
    ])
}

// ── Ukrainian (7 patterns) ──────────────────────────────────────────────────

fn builtin_uk_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "uk_ignorui_instruktsii",
            r"(?i)ігноруй\s+(всі\s+)?(попередні|минулі)\s+(інструкції|вказівки|правила)",
        ),
        ("uk_zabud_vse", r"(?i)забудь\s+все"),
        ("uk_teper_ty", r"(?i)тепер\s+ти\b"),
        ("uk_novi_instruktsii", r"(?i)нові\s+інструкції\s*:"),
        (
            "uk_pokazhy_prompt",
            r"(?i)(покажи|виведи|розкрий)\s+(свій|системний)\s+prompt",
        ),
        ("uk_prykynysa", r"(?i)прикинься[,]?\s+(що|ніби)\b"),
        (
            "uk_bez_obmezhen",
            r"(?i)без\s+(будь-?яких\s+)?(обмежень|правил|заборон)",
        ),
    ])
}

// ── Turkish (8 patterns) ────────────────────────────────────────────────────

fn builtin_tr_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "tr_onceki_talimatlari",
            r"(?i)[oö]nceki\s+(t[uü]m\s+)?(talimatlar[iı]|kurallar[iı])\s+(yok\s+say|g[oö]rmezden\s+gel)",
        ),
        ("tr_hepsini_unut", r"(?i)(hepsini|her\s+[sş]eyi)\s+unut"),
        ("tr_simdi_sen", r"(?i)[sş]imdi\s+sen\s+(bir)\b"),
        ("tr_yeni_talimatlar", r"(?i)yeni\s+talimatlar\s*:"),
        ("tr_sistem_promptu", r"(?i)sistem\s+prompt(u|unu)?\s*:"),
        (
            "tr_goster_prompt",
            r"(?i)(g[oö]ster|a[cç][iı]kla|ortaya\s+[cç][iı]kar)\s+(sistem\s+)?prompt",
        ),
        ("tr_gibi_davran", r"(?i)gibi\s+davran\b"),
        (
            "tr_kisitlama_yok",
            r"(?i)(k[iı]s[iı]tlama|kural|s[iı]n[iı]rlama)\s+(olmadan|yok)",
        ),
    ])
}

// ── Arabic (8 patterns) ─────────────────────────────────────────────────────

fn builtin_ar_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "ar_tajahul_taalimat",
            r"تجاهل\s+(جميع\s+)?(التعليمات|الأوامر|القواعد)\s+(السابقة|القديمة)",
        ),
        ("ar_insa_kulla", r"انس[َ]?\s+(كل\s+شيء|كل\s+ما\s+سبق)"),
        ("ar_anta_alaan", r"أنت\s+الآن\b"),
        ("ar_taalimat_jadida", r"تعليمات\s+جديدة\s*:"),
        ("ar_moht_nizam", r"موجه\s+النظام\s*:"),
        (
            "ar_izhaar_prompt",
            r"(أظهر|اعرض|اكشف)\s+(موجه|تعليمات)\s+النظام",
        ),
        ("ar_tazaahar", r"تظاهر\s+(بأنك|أنك)\b"),
        ("ar_bidun_quyud", r"(بدون|بلا)\s+(أي\s+)?(قيود|قواعد|حدود)"),
    ])
}

// ── Chinese (8 patterns) ────────────────────────────────────────────────────

fn builtin_zh_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "zh_hulue_zhiling",
            r"忽[略视]\s*(所有\s*)?(之前|以前|先前)的?\s*(指[令示]|规则|提示)",
        ),
        ("zh_wangji_yiqian", r"忘(记|掉)\s*(之前|以前)?(所有|一切)"),
        ("zh_xianzai_ni_shi", r"现在你是\s*(一[个個])?"),
        ("zh_xin_zhiling", r"新(的)?指[令示]\s*[：:]"),
        ("zh_xitong_tishi", r"系统提示\s*[：:]"),
        (
            "zh_xianshi_prompt",
            r"(显示|展示|输出|泄露|打印)\s*(你的\s*)?(系统\s*)?(提示[词]?|指[令示])",
        ),
        ("zh_jiazhuang", r"假装\s*(你是|自己是|没有)"),
        ("zh_meiyou_xianzhi", r"没有\s*(任何\s*)?(限制|规则|约束)"),
    ])
}

// ── Japanese (8 patterns) ───────────────────────────────────────────────────

fn builtin_ja_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "ja_mushi_shiji",
            r"(以前|前|すべて|全て)の?\s*(指示|命令|ルール)\s*を?\s*(無視|忽略)|(無視|忽略)\s*(して)?\s*(すべて|全て|以前|前)の?\s*(指示|命令|ルール)",
        ),
        ("ja_wasurete", r"(忘れて|忘却して)\s*(すべて|全て|全部)"),
        ("ja_anata_wa_ima", r"あなたは今\s*(から)?"),
        ("ja_atarashii_shiji", r"新しい指示\s*[：:]"),
        ("ja_system_prompt", r"システムプロンプト\s*[：:]"),
        (
            "ja_hyouji_prompt",
            r"(表示|出力|見せて|漏洩|明かして)\s*(あなたの\s*)?(システム\s*)?プロンプト",
        ),
        ("ja_furi_wo_suru", r"(ふりをして|演じて|なりきって)"),
        (
            "ja_seigen_nashi",
            r"(制限|ルール|規則)\s*(なし|なく|無し|を無視)",
        ),
    ])
}

// ── Korean (8 patterns) ─────────────────────────────────────────────────────

fn builtin_ko_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "ko_musi_jisi",
            r"(모든\s*)?(이전|앞|기존)(의|에)?\s*(지시|명령|규칙|지침)\s*를?\s*(무시|무시해)|(무시|무시해)\s*(모든\s*)?(이전|앞|기존)(의|에)?\s*(지시|명령|규칙|지침)",
        ),
        ("ko_modu_ijeo", r"(모두|전부|다)\s*(잊어|잊어버려|잊으세요)"),
        ("ko_ije_neoneun", r"(이제|지금부터)\s*(너는|당신은)"),
        ("ko_saeroun_jisi", r"새로운\s*지시\s*[：:]"),
        ("ko_siseutem_prompt", r"시스템\s*프롬프트\s*[：:]"),
        (
            "ko_boyeojwo_prompt",
            r"(보여줘|출력해|알려줘|공개해)\s*(너의\s*)?(시스템\s*)?프롬프트",
        ),
        ("ko_cheok", r"(척해|인척해|행세해)"),
        ("ko_jeyak_eobs", r"(제약|규칙|제한)\s*(없이|없는|무시)"),
    ])
}

// ── Hindi (7 patterns) ──────────────────────────────────────────────────────

fn builtin_hi_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "hi_pichhle_nirdesh",
            r"(पिछले|पूर्व|पहले\s+के)\s*(सभी\s+)?(निर्देश|नियम|आदेश)\s*(को\s+)?(अनदेखा|नज़रअंदाज़)\s*(करो|करें|कर)",
        ),
        ("hi_sab_bhool_jao", r"सब\s*(कुछ\s+)?(भूल\s+जाओ|भूल\s+जाएं)"),
        ("hi_ab_tum", r"अब\s+तुम\s+(एक)\b"),
        ("hi_naye_nirdesh", r"नए\s+निर्देश\s*[：:]"),
        (
            "hi_dikhao_prompt",
            r"(दिखाओ|बताओ|प्रकट\s+करो)\s*(अपना\s*)?(सिस्टम\s*)?(प्रॉम्प्ट|निर्देश)",
        ),
        ("hi_dhong_karo", r"(ढोंग|नाटक)\s+करो\s+कि\b"),
        ("hi_bina_niyam", r"बिना\s+(किसी\s+)?(नियम|प्रतिबंध|सीमा)\s+के"),
    ])
}

// ── Thai (6 patterns) ───────────────────────────────────────────────────────

fn builtin_th_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "th_phikhat_khamsung",
            r"(เพิกเฉย|ข้าม|ละเลย)\s*(คำสั่ง|กฎ|คำแนะนำ)\s*(ก่อนหน้า|เดิม|ที่ผ่านมา)",
        ),
        ("th_luem_thangmod", r"ลืม\s*(ทั้งหมด|ทุกอย่าง)"),
        ("th_tawni_khun", r"ตอนนี้คุณ(เป็น|คือ)"),
        ("th_khamsung_mai", r"คำสั่งใหม่\s*[：:]"),
        (
            "th_sadaeng_prompt",
            r"(แสดง|เปิดเผย|บอก)\s*(system\s*)?prompt",
        ),
        ("th_thamthii", r"(แกล้งทำ|ทำเป็น|สมมติว่า)\s*(คุณ|ว่า)"),
    ])
}

// ── Vietnamese (6 patterns) ─────────────────────────────────────────────────

fn builtin_vi_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "vi_bo_qua_chi_thi",
            r"(?i)(bỏ\s+qua|phớt\s+lờ)\s+(tất\s+cả\s+)?(các\s+)?(chỉ\s+thị|hướng\s+dẫn|quy\s+tắc)\s+(trước|cũ)",
        ),
        ("vi_quen_tat_ca", r"(?i)quên\s+(tất\s+cả|hết)"),
        ("vi_bay_gio_ban", r"(?i)bây\s+giờ\s+bạn\s+(là)\b"),
        ("vi_chi_thi_moi", r"(?i)chỉ\s+thị\s+mới\s*:"),
        (
            "vi_hien_thi_prompt",
            r"(?i)(hiển\s+thị|cho\s+xem|tiết\s+lộ)\s+(system\s+)?prompt",
        ),
        ("vi_gia_vo", r"(?i)giả\s+vờ\s+(là|rằng|bạn)\b"),
    ])
}

// ── Indonesian (6 patterns) ─────────────────────────────────────────────────

fn builtin_id_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "id_abaikan_instruksi",
            r"(?i)abaikan\s+(semua\s+)?(instruksi|perintah|aturan)\s+(sebelumnya|lama)",
        ),
        ("id_lupakan_semua", r"(?i)lupakan\s+semua(nya)?"),
        ("id_sekarang_kamu", r"(?i)sekarang\s+kamu\s+(adalah)\b"),
        ("id_instruksi_baru", r"(?i)instruksi\s+baru\s*:"),
        (
            "id_tampilkan_prompt",
            r"(?i)(tampilkan|tunjukkan|ungkapkan)\s+(system\s+)?prompt",
        ),
        ("id_pura_pura", r"(?i)pura-?pura\s+(menjadi|kamu)\b"),
    ])
}

// ── Esperanto (6 patterns) ──────────────────────────────────────────────────

fn builtin_eo_patterns() -> Vec<CompiledPattern> {
    compile_patterns(vec![
        (
            "eo_ignoru_instrukciojn",
            r"(?i)ignor(u|i)\s+([cĉ]iujn\s+)?(anta[uŭ]ajn|antaj?[uŭ]n)\s+(instrukciojn|regulojn|ordonojn)",
        ),
        ("eo_forgesu_cion", r"(?i)forges(u|i)\s+[cĉ]ion"),
        ("eo_nun_vi_estas", r"(?i)nun\s+vi\s+estas\b"),
        ("eo_novaj_instrukcioj", r"(?i)novaj\s+instrukcioj\s*:"),
        (
            "eo_montru_prompt",
            r"(?i)(montru|malka[sŝ]u|rivelu)\s+(la\s+)?(sistema\s+)?prompt",
        ),
        ("eo_pretend_ke", r"(?i)(pretend|[sŝ]ajnigu)\s+ke\b"),
    ])
}
