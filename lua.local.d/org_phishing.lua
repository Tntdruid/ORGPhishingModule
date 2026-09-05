-- ORG_PHISHING: Detects phishing pretending to be known service brands
-- Compatible with Rspamd 4.1.5 (no get_symbols / no get_results)

local logger = require "rspamd_logger"
logger.infox("ORG_PHISHING: lua file loaded")

rspamd_config:register_symbol({
  name = "ORG_PHISHING",
  score = 12.0,
  description = "Detects phishing pretending to be known service brands",
  group = "phishing",

  callback = function(task)
    local matched = false
    local matched_brand = nil

    ----------------------------------------------------------------------
    -- SAFE SUBJECT
    ----------------------------------------------------------------------
    local subject_raw = task:get_header("Subject")
    local subject = subject_raw and tostring(subject_raw):lower() or ""

    ----------------------------------------------------------------------
    -- SAFE BODY
    ----------------------------------------------------------------------
    local body = ""
    local raw = task:get_rawbody()
    if raw then body = body .. " " .. tostring(raw) end
    local c = task:get_content()
    if c then body = body .. " " .. tostring(c) end
    body = body:lower()

    ----------------------------------------------------------------------
    -- SAFE FROM HEADER
    ----------------------------------------------------------------------
    local from = task:get_from("mime")
    if not from or not from[1] then return false end

    local dn = tostring(from[1].name or ""):lower()
    local addr = tostring(from[1].addr or ""):lower()

    ----------------------------------------------------------------------
    -- Legit domain lists
    ----------------------------------------------------------------------
    local legit = {
      ORG_POSTNORD   = { "postnord.dk","postnord.se","postnord.com","postnord.no","postnord.fi" },
      ORG_DHL        = { "dhl.com","dhl.de","dhl.dk","dhl.se","dhl.fi","dhl.no" },
      ORG_GLS        = { "gls.dk","gls.eu","gls-group.eu" },
      ORG_EASYPARK   = { "easypark.net","easypark.dk","easypark.se","easypark.no","easypark.fi","easyparkapp.com","easyparkgroup.com" },
      ORG_SKAT       = { "skat.dk","virk.dk","borger.dk","nemlogin.dk","mitid.dk" },
      ORG_BROBIZZ    = { "brobizz.dk","brobizz.com","brobizz.no","brobizz.se" },
      ORG_MOBILEPAY  = { "mobilepay.dk","mobilepay.fi","mobilepay.no","mobilepay.se" },
      ORG_EBOKS      = { "e-boks.dk","e-boks.com","e-boks.se","e-boks.no","e-boks.fi" },
      ORG_MITID      = { "mitid.dk","nemlogin.dk","borger.dk","virk.dk" },
      ORG_NEMID      = { "nemid.nu","nemlogin.dk","borger.dk","virk.dk" },
      ORG_NETS       = { "nets.eu","nets.dk","nets.no","nets.se","nets.fi" },
      ORG_TDC        = { "tdc.dk","tdcgroup.com" },
      ORG_TELIA      = { "telia.dk","telia.se","telia.no","telia.fi","telia.lt" },
      ORG_YOUSEE     = { "yousee.dk","yousee.tv" },
      ORG_POSTA      = { "posten.no","postnord.no","bring.no" },
      ORG_BRING      = { "bring.no","bring.dk","bring.se","bring.fi" },
      ORG_UPS        = { "ups.com","ups.dk","ups.se","ups.no","ups.fi" },
      ORG_FEDEX      = { "fedex.com","fedex.dk","fedex.se","fedex.no","fedex.fi" },

      ORG_PUNKTUM    = { "punktum.dk" },
      ORG_SYGEFORSIKRING = { "sygeforsikring.dk","danmark.dk" },

      ORG_NETFLIX = {
        "netflix.com","netflix.net","nflxext.com","nflximg.com","nflxvideo.net"
      },

      -- One.com
      ORG_ONECOM = {
        "one.com","one.dk","one.net","onecloud.com"
      }
    }

    ----------------------------------------------------------------------
    -- Helper: domain whitelist check
    ----------------------------------------------------------------------
    local function domain_ok(addr, list)
      for _,d in ipairs(list) do
        if addr:match("@" .. d:gsub("%.", "%%.")) then return true end
      end
      return false
    end

    ----------------------------------------------------------------------
    -- Brand patterns → subsymbol mapping
    ----------------------------------------------------------------------
    local brand_map = {
      { pat = "postnord",        sym = "ORG_POSTNORD" },
      { pat = "dhl",             sym = "ORG_DHL" },
      { pat = "gls",             sym = "ORG_GLS" },

      { pat = "easy[%s%-]*park", sym = "ORG_EASYPARK" },

      { pat = "skat",            sym = "ORG_SKAT" },
      { pat = "skattestyrelsen", sym = "ORG_SKAT" },
      { pat = "brobizz",         sym = "ORG_BROBIZZ" },
      { pat = "mobilepay",       sym = "ORG_MOBILEPAY" },
      { pat = "e%-boks",         sym = "ORG_EBOKS" },
      { pat = "mitid",           sym = "ORG_MITID" },
      { pat = "nemid",           sym = "ORG_NEMID" },
      { pat = "nets",            sym = "ORG_NETS" },
      { pat = "tdc",             sym = "ORG_TDC" },
      { pat = "telia",           sym = "ORG_TELIA" },
      { pat = "yousee",          sym = "ORG_YOUSEE" },
      { pat = "posten",          sym = "ORG_POSTA" },
      { pat = "bring",           sym = "ORG_BRING" },
      { pat = "ups",             sym = "ORG_UPS" },
      { pat = "fedex",           sym = "ORG_FEDEX" },

      { pat = "punktum",         sym = "ORG_PUNKTUM" },
      { pat = "sygeforsikring",  sym = "ORG_SYGEFORSIKRING" },
      { pat = "danmark",         sym = "ORG_SYGEFORSIKRING" },

      { pat = "netflix",         sym = "ORG_NETFLIX" },

      -- One.com
      { pat = "one[%s%-]*com",   sym = "ORG_ONECOM" }
    }

    ----------------------------------------------------------------------
    -- 1) Display name mismatch → brand subsymbols
    ----------------------------------------------------------------------
    for _,b in ipairs(brand_map) do
      if dn:match(b.pat) then
        local whitelist = legit[b.sym]
        if whitelist and not domain_ok(addr, whitelist) then
          matched = true
          matched_brand = b.sym
          task:insert_result(b.sym, 1.0, addr)
        end
      end
    end

    ----------------------------------------------------------------------
    -- 2) URL phishing heuristics (incl. EasyPark + SES + Netflix + One.com)
    ----------------------------------------------------------------------
    local urls = task:get_urls() or {}
    local bad_patterns = {
      "postnord","dhl","gls",
      "easy[%s%-]*park",
      "easypark%-secure","easypark%-payment","easypark%-verify","easypark%-login","easypark%-billing",
      "miportal%-ggs","amazonses",

      "skat","brobizz","mobilepay","e%-boks",
      "mitid","nemid","nets","tdc","telia","yousee",
      "posten","bring","ups","fedex",
      "punktum","sygeforsikring","danmark",

      "netflix","netflix%-secure","netflix%-billing","netflix%-update","netflix%-verify","netflix%-login","nflx",

      -- One.com
      "one[%s%-]*com",
      "onecom%-secure",
      "onecom%-billing",
      "onecom%-update",
      "onecom%-verify",
      "onecom%-login",
      "one%-com",

      "secure","verify","betaling","refund","update","login","track","delivery"
    }

    for _,u in ipairs(urls) do
      local host = tostring(u:get_host() or ""):lower()
      for _,pat in ipairs(bad_patterns) do
        if host:match(pat) then
          matched = true
          task:insert_result("ORG_URL", 1.0, host)
        end
      end
    end

    ----------------------------------------------------------------------
    -- 3) Brand‑specifik DKIM policy
    ----------------------------------------------------------------------
    local dkim = task:get_symbol("DKIM_TRACE") or {}
    local dkim_status = nil

    for _,sym in ipairs(dkim) do
      if sym.options and sym.options[1] then
        local opt = tostring(sym.options[1])
        if opt:match("fail") or opt:match("none") then
          dkim_status = opt
        end
      end
    end

    if dkim_status and matched_brand then
      local critical = {
        ORG_SKAT = true, ORG_MITID = true, ORG_NEMID = true,
        ORG_MOBILEPAY = true, ORG_EBOKS = true, ORG_NETS = true,
        ORG_SYGEFORSIKRING = true
      }

      local medium = {
        ORG_POSTNORD = true, ORG_DHL = true, ORG_GLS = true,
        ORG_BRING = true, ORG_UPS = true, ORG_FEDEX = true, ORG_POSTA = true,
        ORG_PUNKTUM = true,
        ORG_NETFLIX = true,
        ORG_ONECOM = true
      }

      local low = {
        ORG_TDC = true, ORG_TELIA = true, ORG_YOUSEE = true,
        ORG_EASYPARK = true, ORG_BROBIZZ = true
      }

      if critical[matched_brand] then
        matched = true
        task:insert_result("ORG_DKIM_CRITICAL", 1.0, dkim_status)
      elseif medium[matched_brand] then
        matched = true
        task:insert_result("ORG_DKIM_MEDIUM", 1.0, dkim_status)
      elseif low[matched_brand] then
        matched = true
        task:insert_result("ORG_DKIM_LOW", 1.0, dkim_status)
      end
    end

    ----------------------------------------------------------------------
    -- 4) Brand-specifik urgency patterns
    ----------------------------------------------------------------------
    if matched_brand then
      local urgency_patterns = {

        ORG_MITID = {
          "dit mitid er spærret","dit mitid er låst","mitid er midlertidigt deaktiveret",
          "bekræft din identitet","verificer din mitid konto","log ind med mitid"
        },

        ORG_NEMID = {
          "dit nemid er spærret","dit nemid er udløbet","nemid nøgle mangler",
          "bekræft dit nemid","log ind med nemid"
        },

        ORG_MOBILEPAY = {
          "din mobilepay betaling er afvist","mobilepay betaling mangler","mobilepay konto låst",
          "verificer din mobilepay konto","bekræft betaling i mobilepay"
        },

        ORG_EBOKS = {
          "ny besked i e%-boks","vigtig besked i e%-boks","din e%-boks konto er låst",
          "log ind i e%-boks","bekræft din e%-boks identitet"
        },

        ORG_NETS = {
          "nets betaling afvist","nets sikkerhedsopdatering","verificer nets konto","bekræft nets betaling"
        },

        ORG_POSTNORD = {
          "din pakke er på vej","spor din pakke","leveringsproblem",
          "din pakke er tilbageholdt","betaling påkrævet for levering"
        },

        ORG_DHL = {
          "dhl levering forsinket","dhl tracking opdatering","dhl betaling mangler","dhl shipment on hold"
        },

        ORG_GLS = {
          "gls pakke tilbageholdt","gls levering mislykkedes","gls tracking opdatering"
        },

        ORG_BRING = {
          "bring levering forsinket","bring pakke tilbageholdt"
        },

        ORG_POSTA = {
          "posten levering forsinket","posten pakke tilbageholdt"
        },

        ORG_UPS = {
          "ups delivery on hold","ups tracking update","ups payment required"
        },

        ORG_FEDEX = {
          "fedex delivery delayed","fedex shipment on hold","fedex payment required"
        },

        ORG_EASYPARK = {
          "din parkering er ugyldig","betaling for parkering mangler","verificer din easypark konto"
        },

        ORG_BROBIZZ = {
          "brobizz betaling mangler","brobizz opdatering påkrævet","brobizz konto låst"
        },

        ORG_TDC = {
          "tdc betaling mangler","tdc konto låst"
        },

        ORG_TELIA = {
          "telia betaling mangler","telia konto låst"
        },

        ORG_YOUSEE = {
          "yousee betaling mangler","yousee konto låst"
        },

        ORG_NETFLIX = {
          "din netflix betaling er afvist","netflix betaling mangler","din netflix konto er låst",
          "netflix abonnement udløber","netflix subscription expired",
          "update your netflix payment","verify your netflix account",
          "issue with your netflix payment method"
        },

        ORG_ONECOM = {
          "one.com invoice","one.com faktura","one.com payment",
          "one.com domain expires","your domain will expire",
          "domain suspension","verify your one.com account",
          "update your one.com payment","one.com billing issue",
          "one.com account suspended"
        }
      }

      local patterns = urgency_patterns[matched_brand]
      if patterns then
        for _,pat in ipairs(patterns) do
          if subject:match(pat) or body:match(pat) then
            matched = true
            task:insert_result("ORG_URGENCY", 1.0, pat)
          end
        end
      end
    end

    ----------------------------------------------------------------------
    -- Final decision
    ----------------------------------------------------------------------
    if matched then return true end
    return false
  end
})
