package co.predatorhunters.bulwark.camera

import android.content.ContentUris
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.MediaStore
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Built-in (in-app) gallery: a grid of the photos saved by this camera with a
 * full-screen viewer and an "Edit" that hands off to the device photo editor.
 * Querying [MediaStore] without a read-media permission returns the app's OWN
 * contributions on API 29+, which is exactly the shots taken here.
 */
@Composable
internal fun GalleryScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    var images by remember { mutableStateOf<List<Uri>>(emptyList()) }
    var viewing by remember { mutableStateOf<Uri?>(null) }

    LaunchedEffect(Unit) {
        images = withContext(Dispatchers.IO) { loadGalleryImages(context) }
    }

    Box(Modifier.fillMaxSize().background(Ink)) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "✕",
                    color = Color.White,
                    fontSize = 22.sp,
                    modifier = Modifier.clickable(onClick = onClose),
                )
                Spacer(Modifier.width(16.dp))
                Text("Gallery", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
            }
            if (images.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("No photos yet", color = Color.White.copy(alpha = 0.6f), fontSize = 14.sp)
                }
            } else {
                LazyVerticalGrid(columns = GridCells.Fixed(3), modifier = Modifier.fillMaxSize()) {
                    items(images) { uri ->
                        AsyncImage(
                            model = uri,
                            contentDescription = null,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .padding(1.dp)
                                .aspectRatio(1f)
                                .clickable { viewing = uri },
                        )
                    }
                }
            }
        }

        // Full-screen viewer — tap the image to dismiss; "Edit" hands off.
        viewing?.let { uri ->
            Box(Modifier.fillMaxSize().background(Color.Black)) {
                AsyncImage(
                    model = uri,
                    contentDescription = null,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize().clickable { viewing = null },
                )
                Row(
                    Modifier.align(Alignment.TopEnd).padding(20.dp),
                    horizontalArrangement = Arrangement.spacedBy(20.dp),
                ) {
                    PillAction("Edit") { editImage(context, uri) }
                    PillAction("✕") { viewing = null }
                }
            }
        }
    }
}

@Composable
private fun PillAction(label: String, onClick: () -> Unit) {
    Box(
        Modifier
            .clip(RoundedCornerShape(50))
            .background(Color.White.copy(alpha = 0.18f))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Text(label, color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Medium)
    }
}

/** Newest-first list of the app's saved images from MediaStore. */
private fun loadGalleryImages(context: Context): List<Uri> {
    val out = mutableListOf<Uri>()
    val projection = arrayOf(MediaStore.Images.Media._ID)
    val sort = "${MediaStore.Images.Media.DATE_ADDED} DESC"
    runCatching {
        context.contentResolver.query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            projection,
            null,
            null,
            sort,
        )?.use { c ->
            val idCol = c.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
            while (c.moveToNext()) {
                out += ContentUris.withAppendedId(
                    MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                    c.getLong(idCol),
                )
            }
        }
    }
    return out
}

/** Hand the saved photo to the device's photo editor (ACTION_EDIT). */
private fun editImage(context: Context, uri: Uri) {
    runCatching {
        context.startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_EDIT).apply {
                    setDataAndType(uri, "image/*")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                },
                "Edit photo",
            ),
        )
    }
}
