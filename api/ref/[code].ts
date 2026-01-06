export const config = { runtime: 'edge' }

export default async function handler(req: Request) {
  try {
    const url = new URL(req.url)
    const code = decodeURIComponent(url.pathname.replace('/api/ref/', ''))
    if (!code) {
      return new Response(JSON.stringify({ error: 'Referral code missing' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Environment Variables über process.env
    const trackUrl = process.env.SUPABASE_TRACK_REFERRAL_CLICK
    const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY

    if (!trackUrl || !serviceKey) {
      console.error('Environment variables missing')
      return new Response(JSON.stringify({ error: 'Environment variables missing' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Klick tracken (fire-and-forget)
    fetch(trackUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${serviceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ referral_code: code })
    }).catch(err => console.error('Track referral error:', err))

    // Weiterleitung
    const ua = req.headers.get('user-agent') || ''
    let redirectUrl = 'https://play.google.com/store/apps/details?id=deine.app.id'
    if (/iPhone|iPad|iPod/i.test(ua)) {
      redirectUrl = 'https://apps.apple.com/app/idDEINE_APP_ID'
    }

    return Response.redirect(redirectUrl, 302)

  } catch (err) {
    console.error('Referral endpoint error:', err)
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}
