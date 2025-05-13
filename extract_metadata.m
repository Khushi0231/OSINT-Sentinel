% extract_metadata.m
% Read image and extract EXIF metadata
imgInfo = imfinfo('sample_image.jpg');

% Initialize variables for metadata
dateTime = 'Not available';
device = 'Not available';
gpsLat = 'Not available';
gpsLon = 'Not available';

% Extract Date/Time
if isfield(imgInfo, 'DateTime')
    dateTime = imgInfo.DateTime;
end

% Extract Device Info (Make and Model)
if isfield(imgInfo, 'Make') && isfield(imgInfo, 'Model')
    device = sprintf('%s %s', imgInfo.Make, imgInfo.Model);
elseif isfield(imgInfo, 'Make')
    device = imgInfo.Make;
elseif isfield(imgInfo, 'Model')
    device = imgInfo.Model;
end

% Extract GPS Coordinates
if isfield(imgInfo, 'GPSInfo')
    if isfield(imgInfo.GPSInfo, 'GPSLatitude') && isfield(imgInfo.GPSInfo, 'GPSLongitude')
        % Convert GPS coordinates from DMS (degrees, minutes, seconds) to decimal
        lat = imgInfo.GPSInfo.GPSLatitude;
        lon = imgInfo.GPSInfo.GPSLongitude;
        gpsLat = lat(1) + lat(2)/60 + lat(3)/3600;
        gpsLon = lon(1) + lon(2)/60 + lon(3)/3600;
        
        % Adjust for GPS reference (N/S, E/W)
        if isfield(imgInfo.GPSInfo, 'GPSLatitudeRef') && strcmp(imgInfo.GPSInfo.GPSLatitudeRef, 'S')
            gpsLat = -gpsLat;
        end
        if isfield(imgInfo.GPSInfo, 'GPSLongitudeRef') && strcmp(imgInfo.GPSInfo.GPSLongitudeRef, 'W')
            gpsLon = -gpsLon;
        end
    end
end

% Display results
fprintf('Date/Time: %s\n', dateTime);
fprintf('Device: %s\n', device);
fprintf('GPS Latitude: %.6f\n', gpsLat);
fprintf('GPS Longitude: %.6f\n', gpsLon);

% Save metadata to CSV
metadata = {dateTime, device, num2str(gpsLat), num2str(gpsLon)};
csvwrite('metadata.csv', metadata);