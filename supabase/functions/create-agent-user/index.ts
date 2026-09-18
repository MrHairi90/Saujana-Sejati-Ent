import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");

    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: "Unauthorized" }),
        { status: 401, headers: corsHeaders }
      );
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // Client untuk semak siapa yang sedang login
    const userClient = createClient(
      supabaseUrl,
      anonKey,
      {
        global: {
          headers: {
            Authorization: authHeader,
          },
        },
      }
    );

    // Admin client — service role hanya berada di server
    const adminClient = createClient(
      supabaseUrl,
      serviceRoleKey
    );

    const {
      data: { user },
      error: userError,
    } = await userClient.auth.getUser();

    if (userError || !user) {
      return new Response(
        JSON.stringify({ error: "Unauthorized" }),
        { status: 401, headers: corsHeaders }
      );
    }

    // Pastikan yang memanggil function ialah Admin berautoriti
    const { data: adminProfile, error: profileError } =
      await adminClient
        .from("admin_profiles")
        .select("id, role, active")
        .eq("id", user.id)
        .maybeSingle();

    if (
      profileError ||
      !adminProfile ||
      adminProfile.active !== true ||
      !["owner", "manager"].includes(adminProfile.role)
    ) {
      return new Response(
        JSON.stringify({
          error: "Admin tidak dibenarkan.",
        }),
        { status: 403, headers: corsHeaders }
      );
    }

    const body = await req.json();

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const agentId = String(body.agent_id || "");
    const name = String(body.name || "").trim();

    if (!email || !password || !agentId || !name) {
      return new Response(
        JSON.stringify({
          error:
            "Email, password sementara, agent_id dan nama diperlukan.",
        }),
        { status: 400, headers: corsHeaders }
      );
    }

    if (password.length < 8) {
      return new Response(
        JSON.stringify({
          error:
            "Password mesti sekurang-kurangnya 8 aksara.",
        }),
        { status: 400, headers: corsHeaders }
      );
    }

    // Pastikan Agent memang wujud dan aktif
    const { data: agent, error: agentError } =
      await adminClient
        .from("agents")
        .select("id, name, active")
        .eq("id", agentId)
        .maybeSingle();

    if (agentError || !agent) {
      return new Response(
        JSON.stringify({
          error: "Agent tidak dijumpai.",
        }),
        { status: 404, headers: corsHeaders }
      );
    }

    if (agent.active !== true) {
      return new Response(
        JSON.stringify({
          error: "Agent tidak aktif.",
        }),
        { status: 400, headers: corsHeaders }
      );
    }

    // Cegah Agent yang sama mempunyai profile login kedua
    const { data: existingProfile } =
      await adminClient
        .from("agent_profiles")
        .select("id")
        .eq("agent_id", agent.id)
        .maybeSingle();

    if (existingProfile) {
      return new Response(
        JSON.stringify({
          error:
            "Agent ini sudah mempunyai akaun login.",
        }),
        { status: 409, headers: corsHeaders }
      );
    }

    // Cipta akaun Supabase Auth
    const {
      data: created,
      error: createError,
    } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });

    if (createError || !created.user) {
      return new Response(
        JSON.stringify({
          error:
            createError?.message ||
            "Gagal mencipta akaun Agent.",
        }),
        { status: 400, headers: corsHeaders }
      );
    }

    // Sambungkan Auth User dengan Agent
    const {
      error: insertError,
    } = await adminClient
      .from("agent_profiles")
      .insert({
        agent_id: agent.id,
        auth_user_id: created.user.id,
        name,
        active: true,
      });

    // Jika profile gagal dibuat, buang Auth User tadi
    if (insertError) {
      await adminClient.auth.admin.deleteUser(
        created.user.id
      );

      return new Response(
        JSON.stringify({
          error:
            "Akaun dibuat tetapi profile Agent gagal disimpan: " +
            insertError.message,
        }),
        { status: 500, headers: corsHeaders }
      );
    }

    return new Response(
      JSON.stringify({
        ok: true,
        user_id: created.user.id,
        message:
          "Akaun Agent berjaya dicipta.",
      }),
      {
        status: 200,
        headers: corsHeaders,
      }
    );

  } catch (err) {
    return new Response(
      JSON.stringify({
        error:
          err instanceof Error
            ? err.message
            : "Ralat tidak diketahui.",
      }),
      {
        status: 500,
        headers: corsHeaders,
      }
    );
  }
});
