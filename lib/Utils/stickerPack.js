import { createHash } from 'crypto'
import { zipSync } from 'fflate'
import { promises as fs } from 'fs'
import { Boom } from '@hapi/boom'
import { proto } from '../../WAProto/index.js'
import { generateMessageIDV2 } from './generics.js'
import { getImageProcessingLibrary, encryptedStream } from './messages-media.js'

/**
 * Verifica se um buffer é um arquivo WebP válido
 * Valida os magic bytes: RIFF....WEBP
 *
 * @param buffer - Buffer to check
 * @returns true if buffer is valid WebP format
 *
 * @example
 * ```javascript
 * const buffer = await readFile('image.webp')
 * if (isWebPBuffer(buffer)) {
 *   console.log('Valid WebP file')
 * }
 * ```
 */
export const isWebPBuffer = (buffer) => {
	if (buffer.length < 12) return false

	// Verifica magic bytes RIFF (0-3) e WEBP (8-11)
	const riffHeader = buffer.toString('ascii', 0, 4)
	const webpHeader = buffer.toString('ascii', 8, 12)

	return riffHeader === 'RIFF' && webpHeader === 'WEBP'
}

/**
 * Detecta se um WebP é animado através da análise de chunks
 *
 * Analisa a estrutura do arquivo WebP procurando por:
 * - VP8X header com animation flag (bit 1)
 * - Chunks ANIM (animation) ou ANMF (animation frame)
 *
 * SECURITY: Implements robust validation to prevent:
 * - Integer overflow attacks (malicious chunk sizes)
 * - Out-of-bounds reads (buffer overflow)
 * - Infinite loop DoS (iteration limit)
 *
 * @param buffer - WebP buffer to analyze
 * @returns true if WebP is animated, false if static or malformed
 *
 * @example
 * ```javascript
 * const webpBuffer = await readFile('sticker.webp')
 * if (isAnimatedWebP(webpBuffer)) {
 *   console.log('Animated sticker detected')
 * }
 * ```
 */
export const isAnimatedWebP = (buffer) => {
	if (!isWebPBuffer(buffer)) return false

	const MAX_CHUNK_SIZE = 100 * 1024 * 1024 // 100MB max per chunk
	const MAX_ITERATIONS = 1000 // Prevent infinite loop

	let offset = 12 // Skip RIFF header (12 bytes)
	let iterations = 0

	while (offset < buffer.length - 8 && iterations++ < MAX_ITERATIONS) {
		const chunkFourCC = buffer.toString('ascii', offset, offset + 4)
		const chunkSize = buffer.readUInt32LE(offset + 4)

		// SECURITY: Validate chunk size to prevent integer overflow and buffer overflow
		if (chunkSize < 0 || chunkSize > MAX_CHUNK_SIZE) {
			// Invalid chunk size - treat as non-animated
			return false
		}

		// SECURITY: Verify chunk fits within buffer bounds
		if (offset + 8 + chunkSize > buffer.length) {
			// Chunk extends beyond buffer - malformed file
			return false
		}

		// VP8X extended header - check animation flag
		if (chunkFourCC === 'VP8X' && offset + 8 < buffer.length) {
			const flags = buffer[offset + 8]
			// Bit 1 (0x02) = animation flag
			if (flags && (flags & 0x02)) return true
		}

		// Animation chunks
		if (chunkFourCC === 'ANIM' || chunkFourCC === 'ANMF') {
			return true
		}

		// Move to next chunk (8 byte header + chunk size + padding)
		offset += 8 + chunkSize + (chunkSize % 2)
	}

	return false
}

/**
 * Converte uma imagem para WebP usando Sharp
 * Preserva o buffer original se já for WebP para manter EXIF e animações
 *
 * @param buffer - Image buffer to convert
 * @param logger - Optional logger for debugging
 * @returns Object with WebP buffer and animation status
 *
 * @throws {Boom} If Sharp is not installed and buffer is not WebP
 */
const convertToWebP = async (
	buffer,
	logger
) => {
	// Se já é WebP, preserva o buffer original (mantém EXIF e animações)
	if (isWebPBuffer(buffer)) {
		const isAnimated = isAnimatedWebP(buffer)
		logger?.trace({ isAnimated }, 'Input is already WebP, preserving original buffer')
		return { webpBuffer: buffer, isAnimated }
	}

	// Tenta usar Sharp para converter
	const lib = await getImageProcessingLibrary()

	if (!lib?.sharp) {
		throw new Boom(
			'Sharp library is required to convert non-WebP images to WebP format. Install with: yarn add sharp',
			{ statusCode: 400 }
		)
	}

	logger?.trace('Converting image to WebP using Sharp')
	const webpBuffer = await lib.sharp.default(buffer).webp().toBuffer()

	return { webpBuffer, isAnimated: false }
}

/**
 * Gera hash SHA256 em formato base64 URL-safe (RFC 4648)
 * Usado para nomear arquivos de stickers no ZIP (auto-deduplicação)
 *
 * SECURITY: Correctly implements base64url encoding to prevent hash collisions:
 * - '+' → '-'
 * - '/' → '_' (DIFFERENT from '+' mapping)
 * - '=' padding removed
 *
 * @param buffer - Buffer to hash
 * @returns Base64 URL-safe SHA256 hash (RFC 4648 compliant)
 */
const generateSha256Hash = (buffer) => {
	return createHash('sha256')
		.update(buffer)
		.digest('base64')
		.replace(/\+/g, '-') // + becomes -
		.replace(/\//g, '_') // / becomes _ (CRITICAL: different from + mapping!)
		.replace(/=/g, '')   // Remove padding
}

/**
 * Converte WAMediaUpload para Buffer com limites de segurança
 * Suporta Buffer, Stream, URL e Data URLs
 *
 * SECURITY: Implements protections against:
 * - Memory exhaustion (size limits)
 * - Slow read attacks (timeouts)
 * - Resource DoS (stream cleanup)
 *
 * @param media - Media input (Buffer, Stream, URL or Data URL)
 * @param context - Context for error messages (e.g., 'sticker', 'cover')
 * @param options - Optional size limit and timeout
 * @returns Buffer with media content
 *
 * @throws {Boom} If media format is invalid, too large, or timeout
 */
const mediaToBuffer = async (
	media,
	context,
	options
) => {
	const MAX_SIZE = options?.maxSize || 10 * 1024 * 1024 // 10MB default
	const TIMEOUT = options?.timeout || 30000 // 30s default

	if (Buffer.isBuffer(media)) {
		// SECURITY: Validate buffer size
		if (media.length > MAX_SIZE) {
			throw new Boom(`${context} size (${(media.length / 1024).toFixed(2)}KB) exceeds ${MAX_SIZE / 1024}KB limit`, {
				statusCode: 413
			})
		}
		return media
	} else if (typeof media === 'object' && 'url' in media) {
		const url = media.url.toString()

		// ENHANCEMENT: Support Data URLs (data:image/...)
		if (url.startsWith('data:')) {
			try {
				const base64Data = url.split(',')[1]
				if (!base64Data) {
					throw new Boom(`Invalid data URL for ${context}: missing base64 data`, { statusCode: 400 })
				}
				const buffer = Buffer.from(base64Data, 'base64')

				// SECURITY: Validate buffer size
				if (buffer.length > MAX_SIZE) {
					throw new Boom(
						`${context} data URL size (${(buffer.length / 1024).toFixed(2)}KB) exceeds ${MAX_SIZE / 1024}KB limit`,
						{ statusCode: 413 }
					)
				}

				return buffer
			} catch (error) {
				if (error instanceof Boom) throw error
				throw new Boom(`Failed to parse data URL for ${context}: ${error.message}`, {
					statusCode: 400
				})
			}
		}

		// HTTP/HTTPS URLs - download with size limit and timeout
		const controller = new AbortController()
		const timeoutId = setTimeout(() => controller.abort(), TIMEOUT)

		try {
			const response = await fetch(url, {
				signal: controller.signal
			})

			if (!response.ok) {
				throw new Boom(`Failed to download ${context} from URL: ${url}`, {
					statusCode: 400,
					data: { url, status: response.status }
				})
			}

			// SECURITY: Check Content-Length header before downloading
			const contentLength = response.headers.get('content-length')
			if (contentLength && parseInt(contentLength) > MAX_SIZE) {
				throw new Boom(
					`${context} URL file size (${(parseInt(contentLength) / 1024).toFixed(2)}KB) exceeds ${MAX_SIZE / 1024}KB limit`,
					{ statusCode: 413, data: { url, contentLength } }
				)
			}

			// SECURITY: Stream download with size validation
			const chunks = []
			let totalSize = 0

			const reader = response.body.getReader()

			try {
				while (true) {
					const { done, value } = await reader.read()
					if (done) break

					totalSize += value.length
					if (totalSize > MAX_SIZE) {
						throw new Boom(
							`${context} URL download exceeded ${MAX_SIZE / 1024}KB limit during transfer`,
							{ statusCode: 413, data: { url, downloadedSize: totalSize } }
						)
					}

					chunks.push(value)
				}
			} finally {
				reader.releaseLock()
			}

			clearTimeout(timeoutId)
			return Buffer.concat(chunks)
		} catch (error) {
			clearTimeout(timeoutId)

			if (error.name === 'AbortError') {
				throw new Boom(`${context} URL download timeout (${TIMEOUT}ms)`, {
					statusCode: 408,
					data: { url, timeout: TIMEOUT }
				})
			}

			if (error instanceof Boom) throw error

			throw new Boom(`Failed to download ${context} from URL: ${error.message}`, {
				statusCode: 400,
				data: { url, error: error.message }
			})
		}
	} else if (typeof media === 'object' && 'stream' in media) {
		// Stream input
		const stream = media.stream

		return new Promise((resolve, reject) => {
			const chunks = []
			let totalSize = 0
			let timeoutId

			const cleanup = () => {
				if (timeoutId) clearTimeout(timeoutId)
				stream.destroy()
			}

			timeoutId = setTimeout(() => {
				cleanup()
				reject(
					new Boom(`${context} stream read timeout (${TIMEOUT}ms)`, {
						statusCode: 408,
						data: { timeout: TIMEOUT }
					})
				)
			}, TIMEOUT)

			stream.on('data', (chunk) => {
				totalSize += chunk.length
				if (totalSize > MAX_SIZE) {
					cleanup()
					reject(
						new Boom(`${context} stream size exceeded ${MAX_SIZE / 1024}KB limit`, {
							statusCode: 413,
							data: { streamedSize: totalSize }
						})
					)
					return
				}
				chunks.push(chunk)
			})

			stream.on('end', () => {
				clearTimeout(timeoutId)
				resolve(Buffer.concat(chunks))
			})

			stream.on('error', (error) => {
				cleanup()
				reject(new Boom(`${context} stream error: ${error.message}`, { statusCode: 400 }))
			})
		})
	}

	throw new Boom(`Invalid media type for ${context}`, { statusCode: 400 })
}

/**
 * Cria e processa um sticker pack para envio no WhatsApp
 *
 * FEATURES:
 * - Deduplicação automática via SHA256 hashing
 * - Validação de tamanho por sticker (500KB estático, 1MB animado)
 * - Auto-compressão com Sharp quando necessário
 * - Metadata rica (emojis, accessibility labels)
 * - Cover image (tray icon) e thumbnail
 * - ZIP level 0 (sem compressão) para máxima velocidade
 *
 * SECURITY:
 * - Validação de tamanhos (stickers, pack, cover)
 * - Proteção contra duplicatas maliciosas
 * - Error handling contextualizado
 * - Buffer validation e timeouts
 *
 * @param pack - Sticker pack configuration
 * @param uploadMedia - Function to upload encrypted media
 * @param logger - Optional logger
 * @returns StickerPackMessage protobuf ready to send
 *
 * @throws {Boom} If validation fails, conversion fails, or upload fails
 *
 * @example
 * ```javascript
 * const pack = {
 *   name: 'My Pack',
 *   publisher: 'John Doe',
 *   stickers: [
 *     { media: imageBuffer, emojis: ['😀', '😃'] },
 *     { media: { url: 'https://example.com/img.png' } }
 *   ],
 *   cover: coverBuffer
 * }
 *
 * const message = await processStickerPack(pack, uploadMedia, logger)
 * await sock.sendMessage(jid, { stickerPackMessage: message })
 * ```
 */
export const prepareStickerPackMessage = async (
	pack,
	uploadMedia,
	logger
) => {
	const { name, publisher, stickers, cover, description } = pack

	// 1. Validações iniciais
	if (!name || name.trim().length === 0) {
		throw new Boom('Sticker pack name is required', { statusCode: 400 })
	}

	if (!publisher || publisher.trim().length === 0) {
		throw new Boom('Publisher name is required', { statusCode: 400 })
	}

	if (!stickers || !Array.isArray(stickers) || stickers.length === 0) {
		throw new Boom('At least one sticker is required', { statusCode: 400 })
	}

	if (stickers.length > 30) {
		throw new Boom(`Sticker pack cannot have more than 30 stickers (received ${stickers.length})`, {
			statusCode: 400
		})
	}

	if (!cover) {
		throw new Boom('Cover image is required', { statusCode: 400 })
	}

	logger?.info(
		{ name, publisher, totalStickers: stickers.length },
		'Starting sticker pack processing'
	)

	// 2. Gera ID único para o pack (timestamp-based)
	const stickerPackId = generateMessageIDV2()

	// 3. Processa cada sticker com limites de segurança
	const stickerData = {}
	const stickerMetadata = []
	const metadataByHash = new Map()

	logger?.trace({ totalStickers: stickers.length }, 'Processing individual stickers')

	const processedStickers = await Promise.all(
		stickers.map(async (sticker, i) => {
			try {
				logger?.trace({ index: i }, `Processing sticker ${i + 1}/${stickers.length}`)

				// Converte para Buffer
				const buffer = await mediaToBuffer(sticker.media, `sticker ${i + 1}`)

				// Converte para WebP e detecta animação
				const { webpBuffer, isAnimated } = await convertToWebP(buffer, logger)

				// Define limites de tamanho baseado no tipo
				// WhatsApp oficial: 500KB estático, 1MB animado
				const recommendedLimit = isAnimated ? 1024 : 500 // KB

				// Valida tamanho ANTES da compressão
				const originalSizeKB = webpBuffer.length / 1024

				let finalWebpBuffer = webpBuffer

				if (originalSizeKB > recommendedLimit) {
					logger?.debug(
						{ index: i, originalSizeKB, recommendedLimit, isAnimated },
						`Sticker ${i + 1} exceeds recommended size, attempting compression`
					)

					// Tenta comprimir com Sharp
					const lib = await getImageProcessingLibrary()

					if (lib?.sharp && !isAnimated) {
						// Sharp só funciona para stickers estáticos
						try {
							const image = lib.sharp.default(webpBuffer)
							const metadata = await image.metadata()

							// Reduz qualidade progressivamente até atingir o limite
							for (let quality = 85; quality >= 50; quality -= 10) {
								const compressed = await image
									.webp({ quality, effort: 6 })
									.toBuffer()

								const compressedSizeKB = compressed.length / 1024

								logger?.trace(
									{ quality, originalSizeKB, compressedSizeKB, recommendedLimit },
									`Compression attempt`
								)

								if (compressedSizeKB <= recommendedLimit) {
									finalWebpBuffer = compressed
									logger?.info(
										{ index: i, originalSizeKB, compressedSizeKB, quality },
										`Sticker ${i + 1} successfully compressed`
									)
									break
								}
							}
						} catch (compressionError) {
							logger?.warn(
								{ index: i, error: compressionError.message },
								`Failed to compress sticker ${i + 1}, using original`
							)
						}
					} else if (isAnimated) {
						logger?.warn(
							{ index: i, sizeKB: originalSizeKB },
							`Cannot auto-compress animated sticker ${i + 1}. Please provide a smaller file.`
						)
					} else {
						throw new Boom(
							`Sticker ${i + 1} size (${originalSizeKB.toFixed(2)}KB) exceeds recommended ${recommendedLimit}KB and ` +
								`Sharp library required for auto-compression. Install with: yarn add sharp`,
							{ statusCode: 400 }
						)
					}
				}

				// Check recommended size (warning only)
				const finalSizeKB = finalWebpBuffer.length / 1024
				if (finalSizeKB > recommendedLimit) {
					logger?.warn(
						{ index: i, sizeKB: finalSizeKB, recommendedLimit, isAnimated },
						`Sticker ${i + 1} exceeds WhatsApp recommended size (${recommendedLimit}KB). ` +
							`This may cause slower sending or delivery issues.`
					)
				}

				// Gera nome do arquivo: hash.webp (deduplicação automática)
				const sha256Hash = generateSha256Hash(finalWebpBuffer)
				const fileName = `${sha256Hash}.webp`

				logger?.trace(
					{ index: i, fileName, sizeKB: finalSizeKB.toFixed(2), isAnimated },
					'Sticker processed successfully'
				)

				return {
					fileName,
					webpBuffer: finalWebpBuffer,
					isAnimated,
					emojis: sticker.emojis || [],
					accessibilityLabel: sticker.accessibilityLabel
				}
			} catch (error) {
				// SECURITY FIX #8: Wrap errors with sticker context
				throw new Boom(`Failed to process sticker ${i + 1}: ${error.message}`, {
					statusCode: error instanceof Boom ? error.output.statusCode : 500,
					data: { stickerIndex: i, originalError: error }
				})
			}
		})
	)

	// Build stickerData and merge metadata for duplicates
	let duplicateCount = 0
	for (const result of processedStickers) {
		if (!result) continue

		const { fileName, webpBuffer, isAnimated, emojis, accessibilityLabel } = result

		// SECURITY FIX #7: Check if this hash already exists (duplicate sticker)
		const existingMetadata = metadataByHash.get(fileName)

		if (existingMetadata) {
			// Duplicate detected - merge metadata (combine emojis and labels)
			duplicateCount++

			// Merge emojis (deduplicate)
			const mergedEmojis = Array.from(new Set([...existingMetadata.emojis, ...emojis]))
			existingMetadata.emojis = mergedEmojis

			// Merge accessibility labels (concatenate with separator if both exist)
			if (accessibilityLabel) {
				if (existingMetadata.accessibilityLabel) {
					existingMetadata.accessibilityLabel += ` / ${accessibilityLabel}`
				} else {
					existingMetadata.accessibilityLabel = accessibilityLabel
				}
			}

			logger?.debug(
				{ fileName, mergedEmojis, duplicateCount },
				'Duplicate sticker detected - merged metadata'
			)
		} else {
			// New sticker - add to ZIP and create metadata
			stickerData[fileName] = [new Uint8Array(webpBuffer), { level: 0 }]

			const metadata = {
				fileName,
				isAnimated,
				emojis,
				accessibilityLabel,
				isLottie: false,
				mimetype: 'image/webp'
			}

			metadataByHash.set(fileName, metadata)
			stickerMetadata.push(metadata)
		}
	}

	if (duplicateCount > 0) {
		logger?.info(
			{ duplicateCount, uniqueStickers: stickerMetadata.length },
			`Removed ${duplicateCount} duplicate stickers via deduplication`
		)
	}

	// 4. Processa cover image (tray icon)
	// SECURITY FIX #8: Error context for cover processing
	let coverBuffer
	let coverWebP
	let coverFileName

	try {
		logger?.trace('Processing cover image')
		coverBuffer = await mediaToBuffer(cover, 'cover image')

		// Converte cover para WebP e adiciona ao ZIP
		const result = await convertToWebP(coverBuffer, logger)
		coverWebP = result.webpBuffer
		coverFileName = `${stickerPackId}.webp`
		stickerData[coverFileName] = [new Uint8Array(coverWebP), { level: 0 }]
	} catch (error) {
		throw new Boom(`Failed to process cover image: ${error.message}`, {
			statusCode: error instanceof Boom ? error.output.statusCode : 500,
			data: { originalError: error }
		})
	}

	// 5. Cria ZIP (level 0 = sem compressão para velocidade)
	// SECURITY FIX #8: Error context for ZIP creation
	let zipBuffer
	let uniqueFiles

	try {
		uniqueFiles = Object.keys(stickerData).length
		logger?.trace({ totalFiles: uniqueFiles, includingCover: true }, 'Creating ZIP file')

		zipBuffer = Buffer.from(zipSync(stickerData))

		logger?.info({ zipSizeKB: (zipBuffer.length / 1024).toFixed(2) }, 'ZIP file created successfully')

		// Validação de tamanho total (30MB limit para segurança)
		const MAX_PACK_SIZE = 30 * 1024 * 1024
		if (zipBuffer.length > MAX_PACK_SIZE) {
			throw new Boom(
				`Total pack size exceeds ${MAX_PACK_SIZE / 1024 / 1024}MB limit. ` +
					`Current size: ${(zipBuffer.length / 1024 / 1024).toFixed(2)}MB. ` +
					`Try compressing stickers or reducing pack size.`,
				{ statusCode: 400 }
			)
		}
	} catch (error) {
		throw new Boom(`Failed to create ZIP archive: ${error.message}`, {
			statusCode: error instanceof Boom ? error.output.statusCode : 500,
			data: { originalError: error }
		})
	}

	// 6. Upload do ZIP criptografado
	// SECURITY FIX #8: Error context for sticker pack upload
	let stickerPackUpload

	try {
		logger?.trace('Uploading encrypted sticker pack ZIP')
		stickerPackUpload = await uploadMedia(zipBuffer, 'sticker-pack')
	} catch (error) {
		throw new Boom(`Failed to upload sticker pack: ${error.message}`, {
			statusCode: error instanceof Boom ? error.output.statusCode : 500,
			data: { originalError: error }
		})
	}

	// 7. Gera thumbnail 252x252 JPEG
	// SECURITY FIX #8: Error context for thumbnail generation
	let thumbnailBuffer

	try {
		logger?.trace('Generating thumbnail (252x252 JPEG)')
		const lib = await getImageProcessingLibrary()

		if (!lib?.sharp) {
			throw new Boom(
				'Sharp library is required for thumbnail generation. Install with: yarn add sharp',
				{ statusCode: 400 }
			)
		}

		thumbnailBuffer = await lib.sharp
			.default(coverBuffer)
			.resize(252, 252, { fit: 'cover', position: 'center' })
			.jpeg({ quality: 85 })
			.toBuffer()

		logger?.trace({ thumbnailSizeKB: (thumbnailBuffer.length / 1024).toFixed(2) }, 'Thumbnail generated')
	} catch (error) {
		throw new Boom(`Failed to generate thumbnail: ${error.message}`, {
			statusCode: error instanceof Boom ? error.output.statusCode : 500,
			data: { originalError: error }
		})
	}

	// 8. Upload do thumbnail (REUTILIZA mesma mediaKey - requerido pelo protocolo!)
	// SECURITY FIX #8: Error context for thumbnail upload
	let thumbUpload

	try {
		logger?.trace('Uploading thumbnail with same mediaKey')
		thumbUpload = await uploadMedia(thumbnailBuffer, 'thumbnail-sticker-pack', {
			mediaKey: stickerPackUpload.mediaKey // CRÍTICO: mesma chave!
		})
	} catch (error) {
		throw new Boom(`Failed to upload thumbnail: ${error.message}`, {
			statusCode: error instanceof Boom ? error.output.statusCode : 500,
			data: { originalError: error }
		})
	}

	// 9. Monta mensagem protobuf
	logger?.info(
		{
			packId: stickerPackId,
			totalStickers: stickers.length,
			uniqueFiles: uniqueFiles - 1, // minus cover
			zipSizeKB: (zipBuffer.length / 1024).toFixed(2)
		},
		'Sticker pack message prepared successfully'
	)

	return proto.Message.StickerPackMessage.create({
		// Metadata do pack
		stickerPackId,
		name,
		publisher,
		packDescription: description,
		stickerPackOrigin: proto.Message.StickerPackMessage.StickerPackOrigin.USER_CREATED,
		stickerPackSize: zipBuffer.length,
		stickers: stickerMetadata,

		// ZIP file (criptografado)
		fileSha256: stickerPackUpload.fileSha256,
		fileEncSha256: stickerPackUpload.fileEncSha256,
		mediaKey: stickerPackUpload.mediaKey,
		directPath: stickerPackUpload.directPath,
		fileLength: zipBuffer.length,
		mediaKeyTimestamp: stickerPackUpload.mediaKeyTimestamp,

		// Tray icon info
		trayIconFileName: coverFileName,

		// Thumbnail (criptografado com mesma key)
		thumbnailDirectPath: thumbUpload.directPath,
		thumbnailSha256: createHash('sha256').update(thumbnailBuffer).digest(),
		thumbnailEncSha256: thumbUpload.fileEncSha256,
		thumbnailHeight: 252,
		thumbnailWidth: 252,
		imageDataHash: createHash('sha256').update(thumbnailBuffer).digest('base64')
	})
}
