import { useLocal } from '../../Utils.js';
import { applyPresignedUrlsToRecord } from './getSignedUrl.js';

async function TemplateAfterFind(request) {
  if (request.context?.skipPresign) {
    return request.objects;
  }

  if (request.objects.length === 1) {
    if (request.objects) {
      const obj = request.objects[0];
      const FileAdapterId = obj?.get('FileAdapterId') || '';
      if (FileAdapterId || useLocal !== 'true') {
        return [applyPresignedUrlsToRecord(obj)];
      }
    }
  }
}
export default TemplateAfterFind;
