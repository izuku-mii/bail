import { Boom } from '@hapi/boom';
import { randomBytes } from 'crypto';
import { zip } from 'fflate';
import { promises as fs } from 'fs';
import { proto } from '../../WAProto/index.js';
import {
  CALL_AUDIO_PREFIX,
  CALL_VIDEO_PREFIX,
  MEDIA_KEYS,
  URL_REGEX,
  WA_DEFAULT_EPHEMERAL
} from '../Defaults/index.js';
import { WAMessageStatus, WAProto } from '../Types/index.js';
import { isJidGroup, isJidNewsletter, isJidStatusBroadcast, jidNormalizedUser } from '../WABinary/index.js';
import { sha256 } from './crypto.js';
import { generateMessageIDV2, getKeyAuthor, unixTimestampSeconds } from './generics.js';
import {
  downloadContentFromMessage,
  encryptedStream,
  generateThumbnail,
  getAudioDuration,
  getAudioWaveform,
  getImageProcessingLibrary,
  getRawMediaUploadData,
  getStream,
  toBuffer
} from './messages-media.js';

const MIMETYPE_MAP = {
  image: 'image/jpeg',
  video: 'video/mp4',
  document: 'application/pdf',
  audio: 'audio/ogg; codecs=opus',
  sticker: 'image/webp',
  'product-catalog-image': 'image/jpeg'
};

const MessageTypeProto = {
  image: WAProto.Message.ImageMessage,
  video: WAProto.Message.VideoMessage,
  audio: WAProto.Message.AudioMessage,
  sticker: WAProto.Message.StickerMessage,
  document: WAProto.Message.DocumentMessage
};

export const extractUrlFromText = (text) => text.match(URL_REGEX)?.[0];

export const generateLinkPreviewIfRequired = async (
  text,
  getUrlInfo,
  logger
) => {
  const url = extractUrlFromText(text);
  if (!!getUrlInfo && url) {
    try {
      const urlInfo = await getUrlInfo(url);
      return urlInfo;
    } catch (error) {
      logger?.warn({ trace: error.stack }, 'url generation failed');
    }
  }
};

const assertColor = async (color) => {
  let assertedColor;
  if (typeof color === 'number') {
    assertedColor = color > 0 ? color : 0xffffffff + Number(color) + 1;
  } else {
    let hex = color.trim().replace('#', '');
    if (hex.length <= 6) {
      hex = 'FF' + hex.padStart(6, '0');
    }
    assertedColor = parseInt(hex, 16);
  }
  return assertedColor;
};

export const prepareWAMessageMedia = async (
  message,
  options
) => {
  const logger = options.logger;

  let mediaType;
  for (const key of MEDIA_KEYS) {
    if (key in message) {
      mediaType = key;
    }
  }

  if (!mediaType) {
    throw new Boom('Invalid media type', { statusCode: 400 });
  }

  const uploadData = {
    ...message,
    media: message[mediaType]
  };
  delete uploadData[mediaType];

  const cacheableKey =
    typeof uploadData.media === 'object' &&
    'url' in uploadData.media &&
    !!uploadData.media.url &&
    !!options.mediaCache &&
    mediaType + ':' + uploadData.media.url.toString();

  if (mediaType === 'document' && !uploadData.fileName) {
    uploadData.fileName = 'file';
  }

  if (!uploadData.mimetype) {
    uploadData.mimetype = MIMETYPE_MAP[options.mediaTypeOverride || mediaType];
  }

  if (cacheableKey) {
    const mediaBuff = await options.mediaCache.get(cacheableKey);
    if (mediaBuff) {
      logger?.debug({ cacheableKey }, 'got media cache hit');
      const obj = proto.Message.decode(mediaBuff);
      const key = `${mediaType}Message`;
      Object.assign(obj[key], { ...uploadData, media: undefined });
      return obj;
    }
  }

  const isNewsletter = !!options.jid && isJidNewsletter(options.jid);
  if (isNewsletter) {
    logger?.info({ key: cacheableKey }, 'Preparing raw media for newsletter');
    const { filePath, fileSha256, fileLength } = await getRawMediaUploadData(
      uploadData.media,
      options.mediaTypeOverride || mediaType,
      logger
    );

    const fileSha256B64 = fileSha256.toString('base64');
    const { mediaUrl, directPath } = await options.upload(filePath, {
      fileEncSha256B64: fileSha256B64,
      mediaType: mediaType,
      timeoutMs: options.mediaUploadTimeoutMs
    });

    await fs.unlink(filePath);

    const obj = WAProto.Message.fromObject({
      [`${mediaType}Message`]: MessageTypeProto[mediaType].fromObject({
        url: mediaUrl,
        directPath,
        fileSha256,
        fileLength,
        ...uploadData,
        media: undefined
      })
    });

    if (uploadData.ptv) {
      obj.ptvMessage = obj.videoMessage;
      delete obj.videoMessage;
    }

    if (obj.stickerMessage) {
      obj.stickerMessage.stickerSentTs = Date.now();
    }

    if (cacheableKey) {
      logger?.debug({ cacheableKey }, 'set cache');
      await options.mediaCache.set(cacheableKey, WAProto.Message.encode(obj).finish());
    }

    return obj;
  }

  const requiresDurationComputation = mediaType === 'audio' && typeof uploadData.seconds === 'undefined';
  const requiresThumbnailComputation =
    (mediaType === 'image' || mediaType === 'video') && typeof uploadData['jpegThumbnail'] === 'undefined';
  const requiresWaveformProcessing = mediaType === 'audio' && uploadData.ptt === true;
  const requiresAudioBackground = options.backgroundColor && mediaType === 'audio' && uploadData.ptt === true;
  const requiresOriginalForSomeProcessing = requiresDurationComputation || requiresThumbnailComputation;
  
  const { mediaKey, encFilePath, originalFilePath, fileEncSha256, fileSha256, fileLength } = await encryptedStream(
    uploadData.media,
    options.mediaTypeOverride || mediaType,
    {
      logger,
      saveOriginalFileIfRequired: requiresOriginalForSomeProcessing,
      opts: options.options
    }
  );

  const fileEncSha256B64 = fileEncSha256.toString('base64');
  const [{ mediaUrl, directPath }] = await Promise.all([
    (async () => {
      const result = await options.upload(encFilePath, {
        fileEncSha256B64,
        mediaType,
        timeoutMs: options.mediaUploadTimeoutMs
      });
      logger?.debug({ mediaType, cacheableKey }, 'uploaded media');
      return result;
    })(),
    (async () => {
      try {
        if (requiresThumbnailComputation) {
          const { thumbnail, originalImageDimensions } = await generateThumbnail(
            originalFilePath,
            mediaType,
            options
          );
          uploadData.jpegThumbnail = thumbnail;
          if (!uploadData.width && originalImageDimensions) {
            uploadData.width = originalImageDimensions.width;
            uploadData.height = originalImageDimensions.height;
            logger?.debug('set dimensions');
          }
          logger?.debug('generated thumbnail');
        }

        if (requiresDurationComputation) {
          uploadData.seconds = await getAudioDuration(originalFilePath);
          logger?.debug('computed audio duration');
        }

        if (requiresWaveformProcessing) {
          uploadData.waveform = await getAudioWaveform(originalFilePath, logger);
          logger?.debug('processed waveform');
        }

        if (requiresAudioBackground) {
          uploadData.backgroundArgb = await assertColor(options.backgroundColor);
          logger?.debug('computed backgroundColor audio status');
        }
      } catch (error) {
        logger?.warn({ trace: error.stack }, 'failed to obtain extra info');
      }
    })()
  ]).finally(async () => {
    try {
      await fs.unlink(encFilePath);
      if (originalFilePath) {
        await fs.unlink(originalFilePath);
      }
      logger?.debug('removed tmp files');
    } catch (error) {
      logger?.warn('failed to remove tmp file');
    }
  });

  const obj = WAProto.Message.fromObject({
    [`${mediaType}Message`]: MessageTypeProto[mediaType].fromObject({
      url: mediaUrl,
      directPath,
      mediaKey,
      fileEncSha256,
      fileSha256,
      fileLength,
      mediaKeyTimestamp: unixTimestampSeconds(),
      ...uploadData,
      media: undefined
    })
  });

  if (uploadData.ptv) {
    obj.ptvMessage = obj.videoMessage;
    delete obj.videoMessage;
  }

  if (cacheableKey) {
    logger?.debug({ cacheableKey }, 'set cache');
    await options.mediaCache.set(cacheableKey, WAProto.Message.encode(obj).finish());
  }

  return obj;
};

export const prepareDisappearingMessageSettingContent = (ephemeralExpiration) => {
  ephemeralExpiration = ephemeralExpiration || 0;
  const content = {
    ephemeralMessage: {
      message: {
        protocolMessage: {
          type: WAProto.Message.ProtocolMessage.Type.EPHEMERAL_SETTING,
          ephemeralExpiration
        }
      }
    }
  };
  return WAProto.Message.fromObject(content);
};

export const generateForwardMessageContent = (message, forceForward) => {
  let content = message.message;
  if (!content) {
    throw new Boom('no content in message', { statusCode: 400 });
  }

  content = normalizeMessageContent(content);
  content = proto.Message.decode(proto.Message.encode(content).finish());

  let key = Object.keys(content)[0];
  let score = content?.[key]?.contextInfo?.forwardingScore || 0;
  score += message.key.fromMe && !forceForward ? 0 : 1;
  
  if (key === 'conversation') {
    content.extendedTextMessage = { text: content[key] };
    delete content.conversation;
    key = 'extendedTextMessage';
  }

  const key_ = content?.[key];
  if (score > 0) {
    key_.contextInfo = { forwardingScore: score, isForwarded: true };
  } else {
    key_.contextInfo = {};
  }

  return content;
};

export const generateWAMessageContent = async (
  message,
  options
) => {
  let m = {};
  
  if ('text' in message) {
    const extContent = { text: message.text };

    let urlInfo = message.linkPreview;
    if (typeof urlInfo === 'undefined') {
      urlInfo = await generateLinkPreviewIfRequired(message.text, options.getUrlInfo, options.logger);
    }

    if (urlInfo) {
      extContent.matchedText = urlInfo['matched-text'];
      extContent.jpegThumbnail = urlInfo.jpegThumbnail;
      extContent.description = urlInfo.description;
      extContent.title = urlInfo.title;
      extContent.previewType = 0;

      const img = urlInfo.highQualityThumbnail;
      if (img) {
        extContent.thumbnailDirectPath = img.directPath;
        extContent.mediaKey = img.mediaKey;
        extContent.mediaKeyTimestamp = img.mediaKeyTimestamp;
        extContent.thumbnailWidth = img.width;
        extContent.thumbnailHeight = img.height;
        extContent.thumbnailSha256 = img.fileSha256;
        extContent.thumbnailEncSha256 = img.fileEncSha256;
      }
    }

    if (options.backgroundColor) {
      extContent.backgroundArgb = await assertColor(options.backgroundColor);
    }

    if (options.font) {
      extContent.font = options.font;
    }

    m.extendedTextMessage = extContent;
  } else if ('contacts' in message) {
    const contactLen = message.contacts.contacts.length;
    if (!contactLen) {
      throw new Boom('require atleast 1 contact', { statusCode: 400 });
    }

    if (contactLen === 1) {
      m.contactMessage = WAProto.Message.ContactMessage.create(message.contacts.contacts[0]);
    } else {
      m.contactsArrayMessage = WAProto.Message.ContactsArrayMessage.create(message.contacts);
    }
  } else if ('location' in message) {
    m.locationMessage = WAProto.Message.LocationMessage.create(message.location);
  } else if ('react' in message) {
    if (!message.react.senderTimestampMs) {
      message.react.senderTimestampMs = Date.now();
    }
    m.reactionMessage = WAProto.Message.ReactionMessage.create(message.react);
  } else if ('delete' in message) {
    m.protocolMessage = {
      key: message.delete,
      type: WAProto.Message.ProtocolMessage.Type.REVOKE
    };
  } else if ('forward' in message) {
    m = generateForwardMessageContent(message.forward, message.force);
  } else if ('disappearingMessagesInChat' in message) {
    const exp =
      typeof message.disappearingMessagesInChat === 'boolean'
        ? message.disappearingMessagesInChat
          ? WA_DEFAULT_EPHEMERAL
          : 0
        : message.disappearingMessagesInChat;
    m = prepareDisappearingMessageSettingContent(exp);
  } else if ('groupInvite' in message) {
    m.groupInviteMessage = {};
    m.groupInviteMessage.inviteCode = message.groupInvite.inviteCode;
    m.groupInviteMessage.inviteExpiration = message.groupInvite.inviteExpiration;
    m.groupInviteMessage.caption = message.groupInvite.text;
    m.groupInviteMessage.groupJid = message.groupInvite.jid;
    m.groupInviteMessage.groupName = message.groupInvite.subject;

    if (options.getProfilePicUrl) {
      const pfpUrl = await options.getProfilePicUrl(message.groupInvite.jid, 'preview');
      if (pfpUrl) {
        const resp = await fetch(pfpUrl, { method: 'GET', dispatcher: options?.options?.dispatcher });
        if (resp.ok) {
          const buf = Buffer.from(await resp.arrayBuffer());
          m.groupInviteMessage.jpegThumbnail = buf;
        }
      }
    }
  } else if ('stickerPack' in message) {
    m = await prepareStickerPackMessage(message.stickerPack, options);
  } else if ('pin' in message) {
    m.pinInChatMessage = {};
    m.messageContextInfo = {};
    m.pinInChatMessage.key = message.pin;
    m.pinInChatMessage.type = message.type;
    m.pinInChatMessage.senderTimestampMs = Date.now();
    m.messageContextInfo.messageAddOnDurationInSecs = message.type === 1 ? message.time || 86400 : 0;
  } else if ('buttonReply' in message) {
    switch (message.type) {
      case 'template':
        m.templateButtonReplyMessage = {
          selectedDisplayText: message.buttonReply.displayText,
          selectedId: message.buttonReply.id,
          selectedIndex: message.buttonReply.index
        };
        break;
      case 'plain':
        m.buttonsResponseMessage = {
          selectedButtonId: message.buttonReply.id,
          selectedDisplayText: message.buttonReply.displayText,
          type: proto.Message.ButtonsResponseMessage.Type.DISPLAY_TEXT
        };
        break;
    }
  } else if ('ptv' in message && message.ptv) {
    const { videoMessage } = await prepareWAMessageMedia({ video: message.video }, options);
    m.ptvMessage = videoMessage;
  } else if ('product' in message) {
    const { imageMessage } = await prepareWAMessageMedia({ image: message.product.productImage }, options);
    m.productMessage = WAProto.Message.ProductMessage.create({
      ...message,
      product: {
        ...message.product,
        productImage: imageMessage
      }
    });
  } else if ('listReply' in message) {
    m.listResponseMessage = { ...message.listReply };
  } else if ('event' in message) {
    m.eventMessage = {};
    const startTime = Math.floor(message.event.startDate.getTime() / 1000);

    if (message.event.call && options.getCallLink) {
      const token = await options.getCallLink(message.event.call, { startTime });
      m.eventMessage.joinLink = (message.event.call === 'audio' ? CALL_AUDIO_PREFIX : CALL_VIDEO_PREFIX) + token;
    }

    m.messageContextInfo = {
      messageSecret: message.event.messageSecret || randomBytes(32)
    };

    m.eventMessage.name = message.event.name;
    m.eventMessage.description = message.event.description;
    m.eventMessage.startTime = startTime;
    m.eventMessage.endTime = message.event.endDate ? message.event.endDate.getTime() / 1000 : undefined;
    m.eventMessage.isCanceled = message.event.isCancelled ?? false;
    m.eventMessage.extraGuestsAllowed = message.event.extraGuestsAllowed;
    m.eventMessage.isScheduleCall = message.event.isScheduleCall ?? false;
    m.eventMessage.location = message.event.location;
  } else if ('poll' in message) {
    message.poll.selectableCount ||= 0;
    message.poll.toAnnouncementGroup ||= false;

    if (!Array.isArray(message.poll.values)) {
      throw new Boom('Invalid poll values', { statusCode: 400 });
    }

    if (message.poll.selectableCount < 0 || message.poll.selectableCount > message.poll.values.length) {
      throw new Boom(`poll.selectableCount in poll should be >= 0 and <= ${message.poll.values.length}`, {
        statusCode: 400
      });
    }

    m.messageContextInfo = {
      messageSecret: message.poll.messageSecret || randomBytes(32)
    };

    const pollCreationMessage = {
      name: message.poll.name,
      selectableOptionsCount: message.poll.selectableCount,
      options: message.poll.values.map(optionName => ({ optionName }))
    };

    if (message.poll.toAnnouncementGroup) {
      m.pollCreationMessageV2 = pollCreationMessage;
    } else {
      if (message.poll.selectableCount === 1) {
        m.pollCreationMessageV3 = pollCreationMessage;
      } else {
        m.pollCreationMessage = pollCreationMessage;
      }
    }
  } else if ('sharePhoneNumber' in message) {
    m.protocolMessage = {
      type: proto.Message.ProtocolMessage.Type.SHARE_PHONE_NUMBER
    };
  } else if ('requestPhoneNumber' in message) {
    m.requestPhoneNumberMessage = {};
  } else if ('limitSharing' in message) {
    m.protocolMessage = {
      type: proto.Message.ProtocolMessage.Type.LIMIT_SHARING,
      limitSharing: {
        sharingLimited: message.limitSharing === true,
        trigger: 1,
        limitSharingSettingTimestamp: Date.now(),
        initiatedByMe: true
      }
    };
  } else {
    m = await prepareWAMessageMedia(message, options);
  }

  if ('viewOnce' in message && !!message.viewOnce) {
    m = { viewOnceMessage: { message: m } };
  }

  if ('mentions' in message && message.mentions?.length) {
    const messageType = Object.keys(m)[0];
    const key = m[messageType];
    if ('contextInfo' in key && !!key.contextInfo) {
      key.contextInfo.mentionedJid = message.mentions;
    } else if (key) {
      key.contextInfo = {
        mentionedJid: message.mentions
      };
    }
  }

  if ('edit' in message) {
    m = {
      protocolMessage: {
        key: message.edit,
        editedMessage: m,
        timestampMs: Date.now(),
        type: WAProto.Message.ProtocolMessage.Type.MESSAGE_EDIT
      }
    };
  }

  if ('contextInfo' in message && !!message.contextInfo) {
    const messageType = Object.keys(m)[0];
    const key = m[messageType];
    if ('contextInfo' in key && !!key.contextInfo) {
      key.contextInfo = { ...key.contextInfo, ...message.contextInfo };
    } else if (key) {
      key.contextInfo = message.contextInfo;
    }
  }

  return WAProto.Message.create(m);
};

export const generateWAMessageFromContent = (
  jid,
  message,
  options
) => {
  if (!options.timestamp) {
    options.timestamp = new Date();
  }

  const innerMessage = normalizeMessageContent(message);
  const key = getContentType(innerMessage);
  const timestamp = unixTimestampSeconds(options.timestamp);
  const { quoted, userJid } = options;

  if (quoted && !isJidNewsletter(jid)) {
    const participant = quoted.key.fromMe
      ? userJid
      : quoted.participant || quoted.key.participant || quoted.key.remoteJid;

    let quotedMsg = normalizeMessageContent(quoted.message);
    const msgType = getContentType(quotedMsg);
    quotedMsg = proto.Message.create({ [msgType]: quotedMsg[msgType] });

    const quotedContent = quotedMsg[msgType];
    if (typeof quotedContent === 'object' && quotedContent && 'contextInfo' in quotedContent) {
      delete quotedContent.contextInfo;
    }

    const contextInfo = ('contextInfo' in innerMessage[key] && innerMessage[key]?.contextInfo) || {};
    contextInfo.participant = jidNormalizedUser(participant);
    contextInfo.stanzaId = quoted.key.id;
    contextInfo.quotedMessage = quotedMsg;

    if (jid !== quoted.key.remoteJid) {
      contextInfo.remoteJid = quoted.key.remoteJid;
    }

    if (contextInfo && innerMessage[key]) {
      innerMessage[key].contextInfo = contextInfo;
    }
  }

  if (
    !!options?.ephemeralExpiration &&
    key !== 'protocolMessage' &&
    key !== 'ephemeralMessage' &&
    !isJidNewsletter(jid)
  ) {
    innerMessage[key].contextInfo = {
      ...(innerMessage[key].contextInfo || {}),
      expiration: options.ephemeralExpiration || WA_DEFAULT_EPHEMERAL
    };
  }

  message = WAProto.Message.create(message);

  const messageJSON = {
    key: {
      remoteJid: jid,
      fromMe: true,
      id: options?.messageId || generateMessageIDV2()
    },
    message: message,
    messageTimestamp: timestamp,
    messageStubParameters: [],
    participant: isJidGroup(jid) || isJidStatusBroadcast(jid) ? userJid : undefined,
    status: WAMessageStatus.PENDING
  };
  
  return WAProto.WebMessageInfo.fromObject(messageJSON);
};

export const generateWAMessage = async (jid, content, options) => {
  options.logger = options?.logger?.child({ msgId: options.messageId });
  return generateWAMessageFromContent(jid, await generateWAMessageContent(content, { ...options, jid }), options);
};

export const getContentType = (content) => {
  if (content) {
    const keys = Object.keys(content);
    const key = keys.find(k => (k === 'conversation' || k.includes('Message')) && k !== 'senderKeyDistributionMessage');
    return key;
  }
};

export const normalizeMessageContent = (content) => {
  if (!content) {
    return undefined;
  }

  for (let i = 0; i < 5; i++) {
    const inner = getFutureProofMessage(content);
    if (!inner) {
      break;
    }
    content = inner.message;
  }

  return content;

  function getFutureProofMessage(message) {
    return (
      message?.ephemeralMessage ||
      message?.viewOnceMessage ||
      message?.documentWithCaptionMessage ||
      message?.viewOnceMessageV2 ||
      message?.viewOnceMessageV2Extension ||
      message?.editedMessage
    );
  }
};

export const extractMessageContent = (content) => {
  const extractFromTemplateMessage = (msg) => {
    if (msg.imageMessage) {
      return { imageMessage: msg.imageMessage };
    } else if (msg.documentMessage) {
      return { documentMessage: msg.documentMessage };
    } else if (msg.videoMessage) {
      return { videoMessage: msg.videoMessage };
    } else if (msg.locationMessage) {
      return { locationMessage: msg.locationMessage };
    } else {
      return {
        conversation: 'contentText' in msg ? msg.contentText : 'hydratedContentText' in msg ? msg.hydratedContentText : ''
      };
    }
  };

  content = normalizeMessageContent(content);

  if (content?.buttonsMessage) {
    return extractFromTemplateMessage(content.buttonsMessage);
  }

  if (content?.templateMessage?.hydratedFourRowTemplate) {
    return extractFromTemplateMessage(content?.templateMessage?.hydratedFourRowTemplate);
  }

  if (content?.templateMessage?.hydratedTemplate) {
    return extractFromTemplateMessage(content?.templateMessage?.hydratedTemplate);
  }

  if (content?.templateMessage?.fourRowTemplate) {
    return extractFromTemplateMessage(content?.templateMessage?.fourRowTemplate);
  }

  return content;
};

export const getDevice = (id) =>
  /^3A.{18}$/.test(id)
    ? 'ios'
    : /^3E.{20}$/.test(id)
    ? 'web'
    : /^(.{21}|.{32})$/.test(id)
    ? 'android'
    : /^(3F|.{18}$)/.test(id)
    ? 'desktop'
    : 'unknown';

export const updateMessageWithReceipt = (msg, receipt) => {
  msg.userReceipt = msg.userReceipt || [];
  const recp = msg.userReceipt.find(m => m.userJid === receipt.userJid);
  if (recp) {
    Object.assign(recp, receipt);
  } else {
    msg.userReceipt.push(receipt);
  }
};

export const updateMessageWithReaction = (msg, reaction) => {
  const authorID = getKeyAuthor(reaction.key);
  const reactions = (msg.reactions || []).filter(r => getKeyAuthor(r.key) !== authorID);
  reaction.text = reaction.text || '';
  reactions.push(reaction);
  msg.reactions = reactions;
};

export const updateMessageWithPollUpdate = (msg, update) => {
  const authorID = getKeyAuthor(update.pollUpdateMessageKey);
  const reactions = (msg.pollUpdates || []).filter(r => getKeyAuthor(r.pollUpdateMessageKey) !== authorID);
  if (update.vote?.selectedOptions?.length) {
    reactions.push(update);
  }
  msg.pollUpdates = reactions;
};

export const updateMessageWithEventResponse = (msg, update) => {
  const authorID = getKeyAuthor(update.eventResponseMessageKey);
  const responses = (msg.eventResponses || []).filter(r => getKeyAuthor(r.eventResponseMessageKey) !== authorID);
  responses.push(update);
  msg.eventResponses = responses;
};

export function getAggregateVotesInPollMessage({ message, pollUpdates }, meId) {
  const opts =
    message?.pollCreationMessage?.options ||
    message?.pollCreationMessageV2?.options ||
    message?.pollCreationMessageV3?.options ||
    [];
  
  const voteHashMap = opts.reduce((acc, opt) => {
    const hash = sha256(Buffer.from(opt.optionName || '')).toString();
    acc[hash] = {
      name: opt.optionName || '',
      voters: []
    };
    return acc;
  }, {});

  for (const update of pollUpdates || []) {
    const { vote } = update;
    if (!vote) {
      continue;
    }

    for (const option of vote.selectedOptions || []) {
      const hash = option.toString();
      let data = voteHashMap[hash];
      if (!data) {
        voteHashMap[hash] = {
          name: 'Unknown',
          voters: []
        };
        data = voteHashMap[hash];
      }
      voteHashMap[hash].voters.push(getKeyAuthor(update.pollUpdateMessageKey, meId));
    }
  }

  return Object.values(voteHashMap);
}

export function getAggregateResponsesInEventMessage({ eventResponses }, meId) {
  const responseTypes = ['GOING', 'NOT_GOING', 'MAYBE'];
  const responseMap = {};

  for (const type of responseTypes) {
    responseMap[type] = {
      response: type,
      responders: []
    };
  }

  for (const update of eventResponses || []) {
    const responseType = update.eventResponse || 'UNKNOWN';
    if (responseType !== 'UNKNOWN' && responseMap[responseType]) {
      responseMap[responseType].responders.push(getKeyAuthor(update.eventResponseMessageKey, meId));
    }
  }

  return Object.values(responseMap);
}

export const aggregateMessageKeysNotFromMe = (keys) => {
  const keyMap = {};
  for (const { remoteJid, id, participant, fromMe } of keys) {
    if (!fromMe) {
      const uqKey = `${remoteJid}:${participant || ''}`;
      if (!keyMap[uqKey]) {
        keyMap[uqKey] = {
          jid: remoteJid,
          participant: participant,
          messageIds: []
        };
      }
      keyMap[uqKey].messageIds.push(id);
    }
  }
  return Object.values(keyMap);
};

const REUPLOAD_REQUIRED_STATUS = [410, 404];

export const downloadMediaMessage = async (
  message,
  type,
  options,
  ctx
) => {
  const result = await downloadMsg().catch(async error => {
    if (
      ctx &&
      typeof error?.status === 'number' &&
      REUPLOAD_REQUIRED_STATUS.includes(error.status)
    ) {
      ctx.logger.info({ key: message.key }, 'sending reupload media request...');
      message = await ctx.reuploadRequest(message);
      const result = await downloadMsg();
      return result;
    }
    throw error;
  });

  return result;

  async function downloadMsg() {
    const mContent = extractMessageContent(message.message);
    if (!mContent) {
      throw new Boom('No message present', { statusCode: 400, data: message });
    }

    const contentType = getContentType(mContent);
    let mediaType = contentType?.replace('Message', '');
    const media = mContent[contentType];

    if (!media || typeof media !== 'object' || (!('url' in media) && !('thumbnailDirectPath' in media))) {
      throw new Boom(`"${contentType}" message is not a media message`);
    }

    let download;
    if ('thumbnailDirectPath' in media && !('url' in media)) {
      download = {
        directPath: media.thumbnailDirectPath,
        mediaKey: media.mediaKey
      };
      mediaType = 'thumbnail-link';
    } else {
      download = media;
    }

    const stream = await downloadContentFromMessage(download, mediaType, options);
    if (type === 'buffer') {
      const bufferArray = [];
      for await (const chunk of stream) {
        bufferArray.push(chunk);
      }
      return Buffer.concat(bufferArray);
    }

    return stream;
  }
};

export const assertMediaContent = (content) => {
  content = extractMessageContent(content);
  const mediaContent =
    content?.documentMessage ||
    content?.imageMessage ||
    content?.videoMessage ||
    content?.audioMessage ||
    content?.stickerMessage;
  if (!mediaContent) {
    throw new Boom('given message is not a media message', { statusCode: 400, data: content });
  }
  return mediaContent;
};

function isAnimatedWebP(buffer) {
  if (
    buffer.length < 12 ||
    buffer[0] !== 0x52 ||
    buffer[1] !== 0x49 ||
    buffer[2] !== 0x46 ||
    buffer[3] !== 0x46 ||
    buffer[8] !== 0x57 ||
    buffer[9] !== 0x45 ||
    buffer[10] !== 0x42 ||
    buffer[11] !== 0x50
  ) {
    return false;
  }

  let offset = 12;
  while (offset < buffer.length - 8) {
    const chunkFourCC = buffer.toString('ascii', offset, offset + 4);
    const chunkSize = buffer.readUInt32LE(offset + 4);

    if (chunkFourCC === 'VP8X') {
      const flagsOffset = offset + 8;
      if (flagsOffset < buffer.length) {
        const flags = buffer[flagsOffset];
        if (flags & 0x02) {
          return true;
        }
      }
    } else if (chunkFourCC === 'ANIM' || chunkFourCC === 'ANMF') {
      return true;
    }

    offset += 8 + chunkSize + (chunkSize % 2);
  }

  return false;
}

function isWebPBuffer(buffer) {
  return (
    buffer.length >= 12 &&
    buffer[0] === 0x52 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x46 &&
    buffer[8] === 0x57 &&
    buffer[9] === 0x45 &&
    buffer[10] === 0x42 &&
    buffer[11] === 0x50
  );
}

async function prepareStickerPackMessage(stickerPack, options) {
  const { stickers, name, publisher, packId, description } = stickerPack;

  if (stickers.length > 60) {
    throw new Boom('Sticker pack exceeds the maximum limit of 60 stickers', { statusCode: 400 });
  }

  if (stickers.length === 0) {
    throw new Boom('Sticker pack must contain at least one sticker', { statusCode: 400 });
  }

  const stickerPackIdValue = packId || generateMessageIDV2();

  const lib = await getImageProcessingLibrary();
  const stickerData = {};
  const stickerPromises = stickers.map(async (s, i) => {
    const { stream } = await getStream(s.data);
    const buffer = await toBuffer(stream);

    let webpBuffer;
    let isAnimated = false;
    const isWebP = isWebPBuffer(buffer);

    if (isWebP) {
      webpBuffer = buffer;
      isAnimated = isAnimatedWebP(buffer);
    } else if ('sharp' in lib && lib.sharp) {
      webpBuffer = await lib.sharp.default(buffer).webp().toBuffer();
      isAnimated = false;
    } else {
      throw new Boom(
        'No image processing library (sharp) available for converting sticker to WebP. Either install sharp or provide stickers in WebP format.'
      );
    }

    if (webpBuffer.length > 1024 * 1024) {
      throw new Boom(`Sticker at index ${i} exceeds the 1MB size limit`, { statusCode: 400 });
    }

    const hash = sha256(webpBuffer).toString('base64').replace(/\//g, '-');
    const fileName = `${hash}.webp`;
    stickerData[fileName] = [new Uint8Array(webpBuffer), { level: 0 }];
    return {
      fileName,
      mimetype: 'image/webp',
      isAnimated,
      emojis: s.emojis || [],
      accessibilityLabel: s.accessibilityLabel
    };
  });

  const stickerMetadata = await Promise.all(stickerPromises);

  const trayIconFileName = `${stickerPackIdValue}.webp`;
  const { stream: coverStream } = await getStream(stickerPack.cover);
  const coverBuffer = await toBuffer(coverStream);

  let coverWebpBuffer;
  const isCoverWebP = isWebPBuffer(coverBuffer);

  if (isCoverWebP) {
    coverWebpBuffer = coverBuffer;
  } else if ('sharp' in lib && lib.sharp) {
    coverWebpBuffer = await lib.sharp.default(coverBuffer).webp().toBuffer();
  } else {
    throw new Boom(
      'No image processing library (sharp) available for converting cover to WebP. Either install sharp or provide cover in WebP format.'
    );
  }

  stickerData[trayIconFileName] = [new Uint8Array(coverWebpBuffer), { level: 0 }];

  const zipBuffer = await new Promise((resolve, reject) => {
    zip(stickerData, (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(Buffer.from(data));
      }
    });
  });

  const stickerPackSize = zipBuffer.length;

  const stickerPackUpload = await encryptedStream(zipBuffer, 'sticker-pack', {
    logger: options.logger,
    opts: options.options
  });

  const stickerPackUploadResult = await options.upload(stickerPackUpload.encFilePath, {
    fileEncSha256B64: stickerPackUpload.fileEncSha256.toString('base64'),
    mediaType: 'sticker-pack',
    timeoutMs: options.mediaUploadTimeoutMs
  });

  await fs.unlink(stickerPackUpload.encFilePath);

  const stickerPackMessage = {
    name: name,
    publisher: publisher,
    stickerPackId: stickerPackIdValue,
    packDescription: description,
    stickerPackOrigin: WAProto.Message.StickerPackMessage.StickerPackOrigin.USER_CREATED,
    stickerPackSize: stickerPackSize,
    stickers: stickerMetadata,
    fileSha256: stickerPackUpload.fileSha256,
    fileEncSha256: stickerPackUpload.fileEncSha256,
    mediaKey: stickerPackUpload.mediaKey,
    directPath: stickerPackUploadResult.directPath,
    fileLength: stickerPackUpload.fileLength,
    mediaKeyTimestamp: unixTimestampSeconds(),
    trayIconFileName: trayIconFileName
  };

  try {
    let thumbnailBuffer;

    if ('sharp' in lib && lib.sharp) {
      thumbnailBuffer = await lib.sharp.default(coverBuffer).resize(252, 252).jpeg().toBuffer();
    } else if ('jimp' in lib && lib.jimp) {
      const jimpImage = await lib.jimp.Jimp.read(coverBuffer);
      thumbnailBuffer = await jimpImage.resize({ w: 252, h: 252 }).getBuffer('image/jpeg');
    } else {
      throw new Error('No image processing library available for thumbnail generation');
    }

    if (!thumbnailBuffer || thumbnailBuffer.length === 0) {
      throw new Error('Failed to generate thumbnail buffer');
    }

    const thumbUpload = await encryptedStream(thumbnailBuffer, 'thumbnail-sticker-pack', {
      logger: options.logger,
      opts: options.options,
      mediaKey: stickerPackUpload.mediaKey
    });

    const thumbUploadResult = await options.upload(thumbUpload.encFilePath, {
      fileEncSha256B64: thumbUpload.fileEncSha256.toString('base64'),
      mediaType: 'thumbnail-sticker-pack',
      timeoutMs: options.mediaUploadTimeoutMs
    });

    await fs.unlink(thumbUpload.encFilePath);

    Object.assign(stickerPackMessage, {
      thumbnailDirectPath: thumbUploadResult.directPath,
      thumbnailSha256: thumbUpload.fileSha256,
      thumbnailEncSha256: thumbUpload.fileEncSha256,
      thumbnailHeight: 252,
      thumbnailWidth: 252,
      imageDataHash: sha256(thumbnailBuffer).toString('base64')
    });
  } catch (e) {
    options.logger?.warn?.(`Thumbnail generation failed: ${e}`);
  }

  return { stickerPackMessage };
}