import { useQuery } from '@apollo/client';
import { isNonEmptyArray } from '@sniptt/guards';
import { useRecoilValue } from 'recoil';

import { objectMetadataItemsState } from '@/object-metadata/states/objectMetadataItemsState';
import { useGenerateFindManyRecordsForMultipleMetadataItemsQuery } from '@/object-record/hooks/useGenerateFindManyRecordsForMultipleMetadataItemsQuery';
import { useLimitPerMetadataItem } from '@/object-record/relation-picker/hooks/useLimitPerMetadataItem';
import {
  MultiObjectRecordQueryResult,
  useMultiObjectRecordsQueryResultFormattedAsObjectRecordForSelectArray,
} from '@/object-record/relation-picker/hooks/useMultiObjectRecordsQueryResultFormattedAsObjectRecordForSelectArray';
import { SelectedObjectRecordId } from '@/object-record/relation-picker/hooks/useMultiObjectSearch';
import { useOrderByFieldPerMetadataItem } from '@/object-record/relation-picker/hooks/useOrderByFieldPerMetadataItem';
import { isDefined } from '~/utils/isDefined';
import { capitalize } from '~/utils/string/capitalize';

export const useMultiObjectSearchSelectedItemsQuery = ({
  selectedObjectRecordIds,
}: {
  selectedObjectRecordIds: SelectedObjectRecordId[];
}) => {
  const objectMetadataItems = useRecoilValue(objectMetadataItemsState);

  const objectMetadataItemsUsedInSelectedIdsQuery = objectMetadataItems.filter(
    ({ nameSingular }) => {
      return selectedObjectRecordIds.some(({ objectNameSingular }) => {
        return objectNameSingular === nameSingular;
      });
    },
  );

  const selectedIdFilterPerMetadataItem = Object.fromEntries(
    objectMetadataItemsUsedInSelectedIdsQuery
      .map(({ nameSingular }) => {
        const selectedIds = selectedObjectRecordIds
          .filter(
            ({ objectNameSingular }) => objectNameSingular === nameSingular,
          )
          .map(({ id }) => id);

        console.log({
          selectedObjectRecordIds,
          selectedIds,
          nameSingular,
        });

        if (!isNonEmptyArray(selectedIds)) return null;

        return [
          `filter${capitalize(nameSingular)}`,
          {
            id: {
              in: selectedIds,
            },
          },
        ];
      })
      .filter(isDefined),
  );

  const { orderByFieldPerMetadataItem } = useOrderByFieldPerMetadataItem({
    objectMetadataItems: objectMetadataItemsUsedInSelectedIdsQuery,
  });

  const { limitPerMetadataItem } = useLimitPerMetadataItem({
    objectMetadataItems: objectMetadataItemsUsedInSelectedIdsQuery,
  });

  const multiSelectQueryForSelectedIds =
    useGenerateFindManyRecordsForMultipleMetadataItemsQuery({
      objectMetadataItems: objectMetadataItemsUsedInSelectedIdsQuery,
    });

  const {
    loading: selectedObjectRecordsLoading,
    data: selectedObjectRecordsQueryResult,
  } = useQuery<MultiObjectRecordQueryResult>(multiSelectQueryForSelectedIds, {
    variables: {
      ...selectedIdFilterPerMetadataItem,
      ...orderByFieldPerMetadataItem,
      ...limitPerMetadataItem,
    },
  });

  const { objectRecordForSelectArray: selectedObjectRecords } =
    useMultiObjectRecordsQueryResultFormattedAsObjectRecordForSelectArray({
      multiObjectRecordsQueryResult: selectedObjectRecordsQueryResult,
    });

  console.log({
    selectedObjectRecords,
    selectedObjectRecordsLoading,
    selectedObjectRecordsQueryResult,
  });

  return {
    selectedObjectRecordsLoading,
    selectedObjectRecords,
  };
};
