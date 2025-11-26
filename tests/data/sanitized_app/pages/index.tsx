import React from 'react';
import DOMPurify from 'dompurify';

export default function SafePage({ userContent }) {
  // This is SAFE because we sanitize the input
  const sanitizedContent = DOMPurify.sanitize(userContent);

  return (
    <div>
      <h1>Safe Page</h1>
      <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
    </div>
  );
}
