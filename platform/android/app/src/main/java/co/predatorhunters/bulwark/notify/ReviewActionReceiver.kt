package co.predatorhunters.bulwark.notify

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import co.predatorhunters.bulwark.core.RustBridge

/**
 * Handles the **Approve** / **Keep blocked** taps on a guardian alert
 * notification. The decision is routed to the policy engine via the Rust core
 * ([RustBridge.submitReviewDecision]); the policy engine records it and may
 * allowlist the host/hash for this child going forward.
 */
class ReviewActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val alertId = intent.getStringExtra(AlertNotifier.EXTRA_ALERT_ID) ?: return
        val approve = intent.action == AlertNotifier.ACTION_APPROVE
        runCatching {
            RustBridge.ensureLoaded()
            RustBridge.submitReviewDecision(alertId, approve)
        }.onFailure { Log.w(TAG, "submitReviewDecision failed", it) }

        // Clear the notification once acted upon.
        context.getSystemService(NotificationManager::class.java).cancel(alertId.hashCode())
        Log.i(TAG, "review: alert=$alertId approve=$approve")
    }

    private companion object {
        const val TAG = "BulwarkReview"
    }
}
